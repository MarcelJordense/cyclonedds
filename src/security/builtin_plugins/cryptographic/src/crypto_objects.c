/*
 * Copyright(c) 2006 to 2019 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <assert.h>
#include <string.h>
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/hopscotch.h"
#include "dds/ddsrt/types.h"
#include "crypto_objects.h"
#include "crypto_utils.h"

bool crypto_object_valid(CryptoObject *obj, CryptoObjectKind_t kind)
{
  return (obj && obj->kind == kind && obj->handle == (int64_t)(uintptr_t)obj);
}

static uint32_t crypto_object_hash(const void *obj)
{
  const CryptoObject *object = obj;
  const uint64_t c = UINT64_C (16292676669999574021);
  const uint32_t x = (uint32_t)object->handle;
  return (uint32_t)((x * c) >> 32);
}

static int crypto_object_equal(const void *ha, const void *hb)
{
  const CryptoObject *la = ha;
  const CryptoObject *lb = hb;
  return la->handle == lb->handle;
}

void crypto_object_init(CryptoObject *obj, CryptoObjectKind_t kind, CryptoObjectDestructor destructor)
{
  assert(obj);
  obj->kind = kind;
  obj->handle = (int64_t)(uintptr_t)obj;
  obj->destructor = destructor;
  ddsrt_atomic_st32 (&obj->refcount, 1);
}

static void crypto_object_deinit(CryptoObject *obj)
{
  assert(obj);
  obj->handle = DDS_SECURITY_HANDLE_NIL;
  obj->kind = CRYPTO_OBJECT_KIND_UNKNOWN;
  obj->destructor = NULL;
}

void crypto_object_free(CryptoObject *obj)
{
  if (obj && obj->destructor)
    obj->destructor(obj);
}

CryptoObject * crypto_object_keep(CryptoObject *obj)
{
  if (obj)
    ddsrt_atomic_inc32(&obj->refcount);
  return obj;
}

void crypto_object_release(CryptoObject *obj)
{
  if (obj && ddsrt_atomic_dec32_nv(&obj->refcount) == 0)
    crypto_object_free(obj);
}

static uint32_t participant_key_material_hash(const void *obj)
{
  const participant_key_material *object = obj;
  return (uint32_t)object->pp_local_handle;
}

static int participant_key_material_equal(const void *ha, const void *hb)
{
  const participant_key_material *la = ha;
  const participant_key_material *lb = hb;
  return la->pp_local_handle == lb->pp_local_handle;
}

static CryptoObject * participant_key_material_find(const struct CryptoObjectTable *table, const void *arg)
{
  struct participant_key_material template;
  template.pp_local_handle = *(int64_t *)arg;
  return crypto_object_table_find_by_template(table, &template);
}

CryptoObject * crypto_object_table_find_by_template(const struct CryptoObjectTable *table, const void *template)
{
  return (CryptoObject *)ddsrt_hh_lookup(table->htab, template);
}

static CryptoObject * default_crypto_table_find(const struct CryptoObjectTable *table, const void *arg)
{
  struct CryptoObject template;
  template.handle = *(int64_t *)arg;
  return crypto_object_table_find_by_template(table, &template);
}

struct CryptoObjectTable * crypto_object_table_new(CryptoObjectHashFunction hashfnc, CryptoObjectEqualFunction equalfnc, CryptoObjectFindFunction findfnc)
{
  struct CryptoObjectTable *table;
  if (!hashfnc)
    hashfnc = crypto_object_hash;
  if (!equalfnc)
    equalfnc = crypto_object_equal;
  table = ddsrt_malloc(sizeof(*table));
  table->htab = ddsrt_hh_new(32, hashfnc, equalfnc);
  ddsrt_mutex_init(&table->lock);
  table->findfnc = findfnc ? findfnc : default_crypto_table_find;
  return table;
}

void crypto_object_table_free(struct CryptoObjectTable *table)
{
  struct ddsrt_hh_iter it;
  CryptoObject *obj;

  if (!table)
    return;

  ddsrt_mutex_lock(&table->lock);
  for (obj = ddsrt_hh_iter_first(table->htab, &it); obj; obj = ddsrt_hh_iter_next(&it))
  {
    ddsrt_hh_remove(table->htab, obj);
    crypto_object_release(obj);
  }
  ddsrt_hh_free(table->htab);
  ddsrt_mutex_unlock(&table->lock);
  ddsrt_mutex_destroy(&table->lock);
  ddsrt_free(table);
}

CryptoObject * crypto_object_table_insert(struct CryptoObjectTable *table, CryptoObject *object)
{
  CryptoObject *cur;

  assert(table);
  assert(object);

  ddsrt_mutex_lock(&table->lock);
  if (!(cur = crypto_object_keep (table->findfnc(table, &object->handle))))
    ddsrt_hh_add(table->htab, crypto_object_keep(object));
  else
    crypto_object_release(cur);
  ddsrt_mutex_unlock(&table->lock);

  return cur;
}

void crypto_object_table_remove_object(struct CryptoObjectTable *table, CryptoObject *object)
{
  assert (table);
  assert (object);

  ddsrt_mutex_lock (&table->lock);
  ddsrt_hh_remove (table->htab, object);
  ddsrt_mutex_unlock (&table->lock);

  crypto_object_release (object);
}

CryptoObject * crypto_object_table_remove(struct CryptoObjectTable *table, int64_t handle)
{
  CryptoObject *object;
  assert (table);
  ddsrt_mutex_lock (&table->lock);
  if ((object = crypto_object_keep (table->findfnc(table, &handle))))
  {
    ddsrt_hh_remove (table->htab, object);
    crypto_object_release (object);
  }
  ddsrt_mutex_unlock (&table->lock);

  return object;
}

CryptoObject * crypto_object_table_find(struct CryptoObjectTable *table, int64_t handle)
{
  CryptoObject *object;
  assert (table);
  ddsrt_mutex_lock (&table->lock);
  object = crypto_object_keep (table->findfnc(table, &handle));
  ddsrt_mutex_unlock (&table->lock);

  return object;
}

void crypto_object_table_walk(struct CryptoObjectTable *table, CryptoObjectTableCallback callback, void *arg)
{
  struct ddsrt_hh_iter it;
  CryptoObject *obj;
  int r = 1;

  assert(table);
  assert(callback);
  ddsrt_mutex_lock (&table->lock);
  for (obj = ddsrt_hh_iter_first (table->htab, &it); r && obj; obj = ddsrt_hh_iter_next (&it))
    r = callback(obj, arg);
  ddsrt_mutex_unlock(&table->lock);
}

static void master_key_material__free(CryptoObject *obj)
{
  master_key_material *keymat = (master_key_material *)obj;
  if (obj)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_KEY_MATERIAL);
    if (CRYPTO_TRANSFORM_HAS_KEYS(keymat->transformation_kind))
    {
      ddsrt_free (keymat->master_salt);
      ddsrt_free (keymat->master_sender_key);
      ddsrt_free (keymat->master_receiver_specific_key);
    }
    crypto_object_deinit ((CryptoObject *)keymat);
    memset (keymat, 0, sizeof (*keymat));
    ddsrt_free (keymat);
  }
}

master_key_material * crypto_master_key_material_new(DDS_Security_CryptoTransformKind_Enum transform_kind)
{
  master_key_material *keymat = ddsrt_calloc (1, sizeof(*keymat));
  crypto_object_init((CryptoObject *)keymat, CRYPTO_OBJECT_KIND_KEY_MATERIAL, master_key_material__free);
  keymat->transformation_kind = transform_kind;
  if (CRYPTO_TRANSFORM_HAS_KEYS(transform_kind))
  {
    uint32_t key_bytes = CRYPTO_KEY_SIZE_BYTES(keymat->transformation_kind);
    keymat->master_salt = ddsrt_calloc(1, key_bytes);
    keymat->master_sender_key = ddsrt_calloc(1, key_bytes);
    keymat->master_receiver_specific_key = ddsrt_calloc(1, key_bytes);
  }
  return keymat;
}

void crypto_master_key_material_set(master_key_material *dst, const master_key_material *src)
{
  if (CRYPTO_TRANSFORM_HAS_KEYS(dst->transformation_kind) && !CRYPTO_TRANSFORM_HAS_KEYS(src->transformation_kind))
  {
    ddsrt_free(dst->master_salt);
    ddsrt_free(dst->master_sender_key);
    ddsrt_free(dst->master_receiver_specific_key);
  }
  else if (CRYPTO_TRANSFORM_HAS_KEYS(src->transformation_kind))
  {
    uint32_t key_bytes = CRYPTO_KEY_SIZE_BYTES(src->transformation_kind);
    if (!CRYPTO_TRANSFORM_HAS_KEYS(dst->transformation_kind))
    {
      dst->master_salt = ddsrt_calloc(1, key_bytes);
      dst->master_sender_key = ddsrt_calloc(1, key_bytes);
      dst->master_receiver_specific_key = ddsrt_calloc(1, key_bytes);
    }
    memcpy (dst->master_salt, src->master_salt, key_bytes);
    dst->sender_key_id = src->sender_key_id;
    memcpy (dst->master_sender_key, src->master_sender_key, key_bytes);
    /* Fixme: set the receiver specific key? */
    dst->receiver_specific_key_id = 0;
  }
  dst->transformation_kind = src->transformation_kind;
}

static bool generate_session_key(session_key_material *session, DDS_Security_SecurityException *ex)
{
  session->id++;
  session->block_counter = 0;
  return crypto_calculate_session_key(&session->key, session->id, session->master_key_material->master_salt, session->master_key_material->master_sender_key, session->master_key_material->transformation_kind, ex);
}

static void session_key_material__free(CryptoObject *obj)
{
  session_key_material *session = (session_key_material *)obj;
  if (obj)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_SESSION_KEY_MATERIAL);
    CRYPTO_OBJECT_RELEASE(session->master_key_material);
    crypto_object_deinit((CryptoObject *)session);
    memset (session, 0, sizeof (*session));
    ddsrt_free(session);
  }
}

session_key_material * crypto_session_key_material_new(master_key_material *master_key)
{
  session_key_material *session = ddsrt_malloc(sizeof(*session));
  crypto_object_init((CryptoObject *)session, CRYPTO_OBJECT_KIND_SESSION_KEY_MATERIAL, session_key_material__free);
  memset (session->key.data, 0, CRYPTO_KEY_SIZE_MAX);
  session->block_size = CRYPTO_CIPHER_BLOCK_SIZE;
  session->key_size = crypto_get_key_size(master_key->transformation_kind);
  session->id = crypto_get_random_uint32();
  session->init_vector_suffix = crypto_get_random_uint64();
  session->max_blocks_per_session = INT64_MAX; /* FIXME: should be a config parameter */
  session->block_counter = session->max_blocks_per_session;
  session->master_key_material = (master_key_material *)CRYPTO_OBJECT_KEEP(master_key);

  return session;
}

bool crypto_session_key_material_update(session_key_material *session, uint32_t size, DDS_Security_SecurityException *ex)
{
  if (session->block_counter + (size / session->block_size) >= session->max_blocks_per_session)
    return generate_session_key(session, ex);
  return true;
}

static void local_participant_crypto__free(CryptoObject *obj)
{
  local_participant_crypto *participant_crypto = (local_participant_crypto *)obj;
  if (participant_crypto)
  {
    CHECK_CRYPTO_OBJECT_KIND (obj, CRYPTO_OBJECT_KIND_LOCAL_CRYPTO);
    CRYPTO_OBJECT_RELEASE (participant_crypto->session);
    CRYPTO_OBJECT_RELEASE (participant_crypto->key_material);
    crypto_object_deinit ((CryptoObject *)participant_crypto);
    ddsrt_free (participant_crypto);
  }
}

local_participant_crypto * crypto_local_participant_crypto__new(DDS_Security_IdentityHandle participant_identity)
{
  assert (participant_identity);
  assert (sizeof(DDS_Security_ParticipantCryptoHandle) == 8);
  local_participant_crypto *participant_crypto = ddsrt_calloc (1, sizeof(*participant_crypto));
  participant_crypto->identity_handle = participant_identity;
  crypto_object_init ((CryptoObject *)participant_crypto, CRYPTO_OBJECT_KIND_LOCAL_CRYPTO, local_participant_crypto__free);
  return participant_crypto;
}

static void remote_participant_crypto__free(CryptoObject *obj)
{
  remote_participant_crypto *participant_crypto = (remote_participant_crypto *)obj;

  CHECK_CRYPTO_OBJECT_KIND (obj, CRYPTO_OBJECT_KIND_REMOTE_CRYPTO);
  if (participant_crypto)
  {
    CRYPTO_OBJECT_RELEASE (participant_crypto->session);
    crypto_object_table_free (participant_crypto->key_material);
    crypto_object_deinit ((CryptoObject *)participant_crypto);
    ddsrt_free(participant_crypto);
  }
}

remote_participant_crypto * crypto_remote_participant_crypto__new(DDS_Security_IdentityHandle participant_identity)
{
  assert (participant_identity);
  remote_participant_crypto *participant_crypto = ddsrt_calloc (1, sizeof(*participant_crypto));
  crypto_object_init ((CryptoObject *)participant_crypto, CRYPTO_OBJECT_KIND_REMOTE_CRYPTO, remote_participant_crypto__free);
  participant_crypto->identity_handle = participant_identity;
  participant_crypto->key_material = crypto_object_table_new (participant_key_material_hash, participant_key_material_equal, participant_key_material_find);

  return participant_crypto;
}


static void participant_key_material_free(CryptoObject *obj)
{
  participant_key_material *keymaterial = (participant_key_material *)obj;
  CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_PARTICIPANT_KEY_MATERIAL);
  if (keymaterial)
  {
    CRYPTO_OBJECT_RELEASE(keymaterial->P2P_writer_session);
    CRYPTO_OBJECT_RELEASE(keymaterial->P2P_reader_session);
    CRYPTO_OBJECT_RELEASE(keymaterial->P2P_kx_key_material);
    CRYPTO_OBJECT_RELEASE(keymaterial->local_P2P_key_material);
    CRYPTO_OBJECT_RELEASE(keymaterial->remote_key_material);
    crypto_object_table_free(keymaterial->endpoint_relations);
    crypto_object_deinit((CryptoObject *)keymaterial);
    ddsrt_free(keymaterial);
  }
}

participant_key_material * crypto_participant_key_material_new(const local_participant_crypto *pplocal)
{
  participant_key_material *keymaterial = ddsrt_calloc(1, sizeof(*keymaterial));
  crypto_object_init((CryptoObject *)keymaterial, CRYPTO_OBJECT_KIND_PARTICIPANT_KEY_MATERIAL, participant_key_material_free);
  keymaterial->pp_local_handle = pplocal->_parent.handle;
  keymaterial->endpoint_relations = crypto_object_table_new(NULL, NULL, NULL);
  keymaterial->local_P2P_key_material = crypto_master_key_material_new(CRYPTO_TRANSFORMATION_KIND_NONE);
  keymaterial->P2P_kx_key_material = crypto_master_key_material_new(CRYPTO_TRANSFORMATION_KIND_AES256_GCM); /* as defined in table 67 of the DDS Security spec v1.1 */

  return keymaterial;
}

static void endpoint_relation_free(CryptoObject *obj)
{
  endpoint_relation *relation = (endpoint_relation *)obj;
  if (relation)
  {
    CRYPTO_OBJECT_RELEASE(relation->local_crypto);
    CRYPTO_OBJECT_RELEASE(relation->remote_crypto);
    crypto_object_deinit((CryptoObject *)relation);
    ddsrt_free(relation);
  }
}

endpoint_relation * crypto_endpoint_relation_new(DDS_Security_SecureSubmessageCategory_t kind,
    uint32_t key_id, CryptoObject *local_crypto, CryptoObject *remote_crypto)
{
  endpoint_relation *relation = ddsrt_malloc(sizeof(*relation));
  crypto_object_init((CryptoObject *)relation, CRYPTO_OBJECT_KIND_ENDPOINT_RELATION, endpoint_relation_free);

  relation->kind = kind;
  relation->key_id = key_id;
  relation->local_crypto = CRYPTO_OBJECT_KEEP(local_crypto);
  relation->remote_crypto = CRYPTO_OBJECT_KEEP(remote_crypto);

  return relation;
}

static void local_datawriter_crypto__free(CryptoObject *obj)
{
  local_datawriter_crypto *datawriter_crypto = (local_datawriter_crypto *)obj;

  if (obj)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_LOCAL_WRITER_CRYPTO);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer_session_message);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer_session_payload);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer_key_material_message);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer_key_material_payload);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->participant);
    crypto_object_deinit((CryptoObject *)datawriter_crypto);
    ddsrt_free(datawriter_crypto);
  }
}

local_datawriter_crypto * crypto_local_datawriter_crypto__new(const local_participant_crypto *participant,
    DDS_Security_ProtectionKind meta_protection, DDS_Security_BasicProtectionKind data_protection)
{
  local_datawriter_crypto *writer_crypto = ddsrt_calloc(1, sizeof(*writer_crypto));
  crypto_object_init((CryptoObject *)writer_crypto, CRYPTO_OBJECT_KIND_LOCAL_WRITER_CRYPTO, local_datawriter_crypto__free);
  writer_crypto->participant = (local_participant_crypto *)CRYPTO_OBJECT_KEEP(participant);
  writer_crypto->metadata_protectionKind = meta_protection;
  writer_crypto->data_protectionKind = data_protection;
  writer_crypto->is_builtin_participant_volatile_message_secure_writer = false;

  return writer_crypto;
}


static void remote_datawriter_crypto__free(CryptoObject *obj)
{
  remote_datawriter_crypto *datawriter_crypto = (remote_datawriter_crypto *)obj;
  if (datawriter_crypto)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_REMOTE_WRITER_CRYPTO);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->reader_session);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->reader2writer_key_material);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer2reader_key_material[0]);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->writer2reader_key_material[1]);
    CRYPTO_OBJECT_RELEASE(datawriter_crypto->participant);
    crypto_object_deinit((CryptoObject *)datawriter_crypto);
    ddsrt_free(datawriter_crypto);
  }
}

remote_datawriter_crypto * crypto_remote_datawriter_crypto__new(const remote_participant_crypto *participant,
    DDS_Security_ProtectionKind meta_protection, DDS_Security_BasicProtectionKind data_protection, DDS_Security_DatareaderCryptoHandle local_reader_handle)
{
  remote_datawriter_crypto *writer_crypto = ddsrt_calloc(1, sizeof(*writer_crypto));
  crypto_object_init((CryptoObject *)writer_crypto, CRYPTO_OBJECT_KIND_REMOTE_WRITER_CRYPTO, remote_datawriter_crypto__free);
  writer_crypto->participant = (remote_participant_crypto *)CRYPTO_OBJECT_KEEP(participant);
  writer_crypto->metadata_protectionKind = meta_protection;
  writer_crypto->data_protectionKind = data_protection;
  writer_crypto->local_reader_handle = local_reader_handle;
  writer_crypto->is_builtin_participant_volatile_message_secure_writer = false;

  return writer_crypto;
}


static void local_datareader_crypto__free(CryptoObject *obj)
{
  local_datareader_crypto *datareader_crypto = (local_datareader_crypto *)obj;
  if (datareader_crypto)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_LOCAL_READER_CRYPTO);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->reader_session);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->reader_key_material);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->participant);
    crypto_object_deinit((CryptoObject *)datareader_crypto);
    ddsrt_free(datareader_crypto);
  }
}

local_datareader_crypto * crypto_local_datareader_crypto__new(const local_participant_crypto *participant,
    DDS_Security_ProtectionKind meta_protection, DDS_Security_BasicProtectionKind data_protection)
{
  local_datareader_crypto *reader_crypto = ddsrt_calloc(1, sizeof(*reader_crypto));
  crypto_object_init((CryptoObject *)reader_crypto, CRYPTO_OBJECT_KIND_LOCAL_READER_CRYPTO, local_datareader_crypto__free);
  reader_crypto->participant = (local_participant_crypto *)CRYPTO_OBJECT_KEEP(participant);
  reader_crypto->metadata_protectionKind = meta_protection;
  reader_crypto->data_protectionKind = data_protection;
  reader_crypto->is_builtin_participant_volatile_message_secure_reader = false;

  return reader_crypto;
}


static void remote_datareader_crypto__free(CryptoObject *obj)
{
  remote_datareader_crypto *datareader_crypto = (remote_datareader_crypto *)obj;
  if (datareader_crypto)
  {
    CHECK_CRYPTO_OBJECT_KIND(obj, CRYPTO_OBJECT_KIND_REMOTE_READER_CRYPTO);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->writer_session);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->reader2writer_key_material);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->writer2reader_key_material_message);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->writer2reader_key_material_payload);
    CRYPTO_OBJECT_RELEASE(datareader_crypto->participant);
    crypto_object_deinit((CryptoObject *)datareader_crypto);
    ddsrt_free(datareader_crypto);
  }
}

remote_datareader_crypto *crypto_remote_datareader_crypto__new(const remote_participant_crypto *participant, DDS_Security_ProtectionKind metadata_protectionKind,
    DDS_Security_BasicProtectionKind data_protectionKind, DDS_Security_DatawriterCryptoHandle local_writer_handle)
{
  remote_datareader_crypto *reader_crypto = ddsrt_calloc(1, sizeof(*reader_crypto));
  crypto_object_init((CryptoObject *)reader_crypto, CRYPTO_OBJECT_KIND_REMOTE_READER_CRYPTO, remote_datareader_crypto__free);
  reader_crypto->participant = (remote_participant_crypto *)CRYPTO_OBJECT_KEEP(participant);
  reader_crypto->metadata_protectionKind = metadata_protectionKind;
  reader_crypto->data_protectionKind = data_protectionKind;
  reader_crypto->local_writer_handle = local_writer_handle;
  reader_crypto->is_builtin_participant_volatile_message_secure_reader = false;

  return reader_crypto;
}


typedef struct endpoint_relation_find_arg
{
  CryptoObject *found;
  CryptoObject *local_crypto;
  CryptoObject *remote_crypto;
  uint32_t key_id;
} endpoint_relation_find_arg;

static int endpoint_relation_cmp_key(CryptoObject *obj, void *arg)
{
  const endpoint_relation *rel = (const endpoint_relation *)obj;
  endpoint_relation_find_arg *find_arg = (endpoint_relation_find_arg *)arg;

  if (rel->key_id == find_arg->key_id)
  {
    find_arg->found = crypto_object_keep(obj);
    return 0;
  }
  return 1;
}

static int endpoint_relation_cmp_crypto(CryptoObject *obj, void *arg)
{
  const endpoint_relation *rel = (const endpoint_relation *)obj;
  endpoint_relation_find_arg *find_arg = (endpoint_relation_find_arg *)arg;

  if ((rel->local_crypto == find_arg->local_crypto) &&
      (rel->remote_crypto == find_arg->remote_crypto))
  {
    find_arg->found = crypto_object_keep(obj);
    return 0;
  }
  return 1;
}

endpoint_relation * crypto_endpoint_relation_find_by_key(struct CryptoObjectTable *table, uint32_t key_id)
{
  endpoint_relation_find_arg find_arg;
  find_arg.found = NULL;
  find_arg.key_id = key_id;
  find_arg.local_crypto = NULL;
  find_arg.remote_crypto = NULL;
  crypto_object_table_walk(table, endpoint_relation_cmp_key, &find_arg);
  return (endpoint_relation *)(find_arg.found);
}

endpoint_relation * crypto_endpoint_relation_find_by_crypto(struct CryptoObjectTable *table, CryptoObject *local_crypto, CryptoObject *remote_crypto)
{
  endpoint_relation_find_arg find_arg;
  find_arg.found = NULL;
  find_arg.key_id = 0;
  find_arg.local_crypto = local_crypto;
  find_arg.remote_crypto = remote_crypto;
  crypto_object_table_walk(table, endpoint_relation_cmp_crypto, &find_arg);
  return (endpoint_relation *)(find_arg.found);
}
