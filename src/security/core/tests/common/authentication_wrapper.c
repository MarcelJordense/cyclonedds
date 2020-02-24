/*
 * Copyright(c) 2006 to 2020 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <string.h>
#include <stdio.h>
#include "dds/dds.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/security/dds_security_api.h"
#include "dds/security/core/dds_security_utils.h"
#include "authentication_wrapper.h"
#include "msg_q.h"

#define TEST_IDENTITY_CERTIFICATE_ALL_OK "testtext_IdentityCertificate_testtext"
#define TEST_CA_CERTIFICATE_ALL_OK       "testtext_IdentityCA_testtext"
#define TEST_PRIVATE_KEY_ALL_OK          "testtext_PrivateKey_testtext"

int32_t init_authentication(const char *argument, void **context);
int32_t finalize_authentication(void *context);

enum auth_plugin_mode {
  PLUGIN_MODE_ALL_OK,
  PLUGIN_MODE_WRAPPED,
  PLUGIN_MODE_MISSING_FUNC,
  PLUGIN_MODE_INIT_FAIL
};

/**
 * Implementation structure for storing encapsulated members of the instance
 * while giving only the interface definition to user
 */
struct dds_security_authentication_impl
{
  dds_security_authentication base;
  dds_security_authentication *instance;
  struct message_queue msg_queue;
  const struct ddsi_domaingv *gv;
  enum auth_plugin_mode mode;
};

static struct dds_security_authentication_impl **auth_impl;
static size_t auth_impl_count = 0;

static const char *test_identity_certificate = TEST_IDENTITY_CERTIFICATE_ALL_OK;
static const char *test_ca_certificate       = TEST_CA_CERTIFICATE_ALL_OK;
static const char *test_private_key          = TEST_PRIVATE_KEY_ALL_OK;

static DDS_Security_ValidationResult_t test_validate_local_identity_all_ok(
    DDS_Security_GUID_t *adjusted_participant_guid,
    const DDS_Security_Qos *participant_qos,
    const DDS_Security_GUID_t *candidate_participant_guid)
{
  DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
  char *identity_ca = NULL;
  char *identity_certificate = NULL;
  char *private_key = NULL;

  memcpy(adjusted_participant_guid, candidate_participant_guid, sizeof(*adjusted_participant_guid));
  for (unsigned i = 0; i < participant_qos->property.value._length; i++)
  {
    printf("%s\n", participant_qos->property.value._buffer[i].name);
    if (!strcmp(participant_qos->property.value._buffer[i].name, "dds.sec.auth.private_key"))
      private_key = participant_qos->property.value._buffer[i].value;
    else if (!strcmp(participant_qos->property.value._buffer[i].name, "dds.sec.auth.identity_ca"))
      identity_ca = participant_qos->property.value._buffer[i].value;
    else if (!strcmp(participant_qos->property.value._buffer[i].name, "dds.sec.auth.identity_certificate"))
      identity_certificate = participant_qos->property.value._buffer[i].value;
  }

  if (strcmp(identity_certificate, test_identity_certificate))
  {
    printf("identity received=%s\n", identity_certificate);
    printf("identity expected=%s\n", test_identity_certificate);
    result = DDS_SECURITY_VALIDATION_FAILED;
    printf("FAILED: Could not get identity_certificate value properly\n");
  }
  else if (strcmp(identity_ca, test_ca_certificate))
  {
    printf("ca received=%s\n", identity_ca);
    printf("ca expected=%s\n", test_ca_certificate);
    printf("FAILED: Could not get identity_ca value properly\n");
    result = DDS_SECURITY_VALIDATION_FAILED;
  }
  else if (strcmp(private_key, test_private_key))
  {
    printf("FAILED: Could not get private_key value properly\n");
    result = DDS_SECURITY_VALIDATION_FAILED;
  }
  if (result == DDS_SECURITY_VALIDATION_OK)
    printf("DDS_SECURITY_VALIDATION_OK\n");

  return result;
}

static DDS_Security_ValidationResult_t test_validate_local_identity(
    dds_security_authentication *instance,
    DDS_Security_IdentityHandle *local_identity_handle,
    DDS_Security_GUID_t *adjusted_participant_guid,
    const DDS_Security_DomainId domain_id,
    const DDS_Security_Qos *participant_qos,
    const DDS_Security_GUID_t *candidate_participant_guid,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
    {
      DDS_Security_ValidationResult_t result = impl->instance->validate_local_identity(
          impl->instance, local_identity_handle, adjusted_participant_guid, domain_id, participant_qos, candidate_participant_guid, ex);
      add_message(&impl->msg_queue, MESSAGE_KIND_VALIDATE_LOCAL_IDENTITY, *local_identity_handle, 0, 0, adjusted_participant_guid, NULL, result, NULL, instance);
      return result;
    }
    case PLUGIN_MODE_ALL_OK:
    default:
      return test_validate_local_identity_all_ok(adjusted_participant_guid, participant_qos, candidate_participant_guid);
  }
}

static DDS_Security_boolean test_get_identity_token(dds_security_authentication *instance,
    DDS_Security_IdentityToken *identity_token,
    const DDS_Security_IdentityHandle handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->get_identity_token(impl->instance, identity_token, handle, ex);

    case PLUGIN_MODE_ALL_OK:
    default:
    {
      memset(identity_token, 0, sizeof(*identity_token));
      identity_token->class_id = ddsrt_strdup("");
      return true;
    }
  }
}

static DDS_Security_boolean test_get_identity_status_token(
    dds_security_authentication *instance,
    DDS_Security_IdentityStatusToken *identity_status_token,
    const DDS_Security_IdentityHandle handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->get_identity_status_token(impl->instance, identity_status_token, handle, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_set_permissions_credential_and_token(
    dds_security_authentication *instance,
    const DDS_Security_IdentityHandle handle,
    const DDS_Security_PermissionsCredentialToken *permissions_credential,
    const DDS_Security_PermissionsToken *permissions_token,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->set_permissions_credential_and_token(impl->instance, handle, permissions_credential, permissions_token, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_ValidationResult_t test_validate_remote_identity(
    dds_security_authentication *instance,
    DDS_Security_IdentityHandle *remote_identity_handle,
    DDS_Security_AuthRequestMessageToken *local_auth_request_token,
    const DDS_Security_AuthRequestMessageToken *remote_auth_request_token,
    const DDS_Security_IdentityHandle local_identity_handle,
    const DDS_Security_IdentityToken *remote_identity_token,
    const DDS_Security_GUID_t *remote_participant_guid,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
    {
      DDS_Security_ValidationResult_t result = impl->instance->validate_remote_identity(
        impl->instance, remote_identity_handle, local_auth_request_token, remote_auth_request_token,
        local_identity_handle, remote_identity_token, remote_participant_guid, ex);
      add_message(&impl->msg_queue, MESSAGE_KIND_VALIDATE_REMOTE_IDENTITY, local_identity_handle, *remote_identity_handle, 0, NULL, remote_participant_guid, result, local_auth_request_token, instance);
      return result;
    }

    case PLUGIN_MODE_ALL_OK:
    default:
      return DDS_SECURITY_VALIDATION_OK;
  }
}

static DDS_Security_ValidationResult_t test_begin_handshake_request(
    dds_security_authentication *instance,
    DDS_Security_HandshakeHandle *handshake_handle,
    DDS_Security_HandshakeMessageToken *handshake_message,
    const DDS_Security_IdentityHandle initiator_identity_handle,
    const DDS_Security_IdentityHandle replier_identity_handle,
    const DDS_Security_OctetSeq *serialized_local_participant_data,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
    {
      DDS_Security_ValidationResult_t result = impl->instance->begin_handshake_request(
        impl->instance, handshake_handle, handshake_message, initiator_identity_handle,
        replier_identity_handle, serialized_local_participant_data, ex);
      add_message(&impl->msg_queue, MESSAGE_KIND_BEGIN_HANDSHAKE_REQUEST, initiator_identity_handle, replier_identity_handle, *handshake_handle, NULL, NULL, result, handshake_message, instance);
      return result;
    }

    case PLUGIN_MODE_ALL_OK:
    default:
      return DDS_SECURITY_VALIDATION_OK;
  }
}

static DDS_Security_ValidationResult_t test_begin_handshake_reply(
    dds_security_authentication *instance,
    DDS_Security_HandshakeHandle *handshake_handle,
    DDS_Security_HandshakeMessageToken *handshake_message_out,
    const DDS_Security_HandshakeMessageToken *handshake_message_in,
    const DDS_Security_IdentityHandle initiator_identity_handle,
    const DDS_Security_IdentityHandle replier_identity_handle,
    const DDS_Security_OctetSeq *serialized_local_participant_data,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
    {
      DDS_Security_ValidationResult_t result = impl->instance->begin_handshake_reply(
        impl->instance, handshake_handle, handshake_message_out, handshake_message_in,
        initiator_identity_handle, replier_identity_handle, serialized_local_participant_data, ex);
      add_message(&impl->msg_queue, MESSAGE_KIND_BEGIN_HANDSHAKE_REPLY, replier_identity_handle, initiator_identity_handle, *handshake_handle, NULL, NULL, result, handshake_message_out, instance);
      return result;
    }

    case PLUGIN_MODE_ALL_OK:
    default:
      return DDS_SECURITY_VALIDATION_OK;
  }
}

static DDS_Security_ValidationResult_t test_process_handshake(
    dds_security_authentication *instance,
    DDS_Security_HandshakeMessageToken *handshake_message_out,
    const DDS_Security_HandshakeMessageToken *handshake_message_in,
    const DDS_Security_HandshakeHandle handshake_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
    {
      DDS_Security_ValidationResult_t result = impl->instance->process_handshake(impl->instance, handshake_message_out, handshake_message_in, handshake_handle, ex);
      add_message(&impl->msg_queue, MESSAGE_KIND_PROCESS_HANDSHAKE, 0, 0, handshake_handle, NULL, NULL, result, handshake_message_out, instance);
      return result;
    }

    case PLUGIN_MODE_ALL_OK:
    default:
      return DDS_SECURITY_VALIDATION_OK;
  }
}

static DDS_Security_SharedSecretHandle test_get_shared_secret(
    dds_security_authentication *instance,
    const DDS_Security_HandshakeHandle handshake_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->get_shared_secret(impl->instance, handshake_handle, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return 0;
  }
}

static DDS_Security_boolean test_get_authenticated_peer_credential_token(
    dds_security_authentication *instance,
    DDS_Security_AuthenticatedPeerCredentialToken *peer_credential_token,
    const DDS_Security_HandshakeHandle handshake_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->get_authenticated_peer_credential_token(impl->instance, peer_credential_token, handshake_handle, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_set_listener(dds_security_authentication *instance,
    const dds_security_authentication_listener *listener,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->set_listener(impl->instance, listener, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_return_identity_token(dds_security_authentication *instance,
    const DDS_Security_IdentityToken *token,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_identity_token(impl->instance, token, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      if (token->class_id)
        ddsrt_free (token->class_id);
      return true;
  }
}

static DDS_Security_boolean test_return_identity_status_token(
    dds_security_authentication *instance,
    const DDS_Security_IdentityStatusToken *token,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_identity_status_token(impl->instance, token, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_return_authenticated_peer_credential_token(
    dds_security_authentication *instance,
    const DDS_Security_AuthenticatedPeerCredentialToken *peer_credential_token,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_authenticated_peer_credential_token(impl->instance, peer_credential_token, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_return_handshake_handle(dds_security_authentication *instance,
    const DDS_Security_HandshakeHandle handshake_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_handshake_handle(impl->instance, handshake_handle, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static DDS_Security_boolean test_return_identity_handle(
    dds_security_authentication *instance,
    const DDS_Security_IdentityHandle identity_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_identity_handle(impl->instance, identity_handle, ex);
    default:
      return true;
  }
}

static DDS_Security_boolean test_return_sharedsecret_handle(
    dds_security_authentication *instance,
    const DDS_Security_SharedSecretHandle sharedsecret_handle,
    DDS_Security_SecurityException *ex)
{
  struct dds_security_authentication_impl *impl = (struct dds_security_authentication_impl *)instance;
  switch (impl->mode)
  {
    case PLUGIN_MODE_WRAPPED:
      return impl->instance->return_sharedsecret_handle(impl->instance, sharedsecret_handle, ex);
    case PLUGIN_MODE_ALL_OK:
    default:
      return true;
  }
}

static struct dds_security_authentication_impl * get_impl_for_domain(dds_domainid_t domain_id)
{
  for (size_t i = 0; i < auth_impl_count; i++)
  {
    if (auth_impl[i]->gv->config.domainId == domain_id)
    {
      assert(auth_impl[i]);
      return auth_impl[i];
    }
  }
  return NULL;
}

struct message * test_authentication_plugin_take_msg(dds_domainid_t domain_id, message_kind_t kind, DDS_Security_IdentityHandle lidHandle, DDS_Security_IdentityHandle ridHandle, DDS_Security_IdentityHandle hsHandle, dds_duration_t timeout)
{
  struct dds_security_authentication_impl *impl = get_impl_for_domain(domain_id);
  assert(impl);
  return take_message(&impl->msg_queue, kind, lidHandle, ridHandle, hsHandle, timeout);
}

void test_authentication_plugin_release_msg(struct message *msg)
{
  delete_message(msg);
}

static struct dds_security_authentication_impl * init_test_authentication_common()
{
  struct dds_security_authentication_impl * impl = ddsrt_malloc(sizeof(*impl));
  memset(impl, 0, sizeof(*impl));
  impl->base.validate_local_identity = &test_validate_local_identity;
  impl->base.get_identity_token = &test_get_identity_token;
  impl->base.get_identity_status_token = &test_get_identity_status_token;
  impl->base.set_permissions_credential_and_token = &test_set_permissions_credential_and_token;
  impl->base.validate_remote_identity = &test_validate_remote_identity;
  impl->base.begin_handshake_request = &test_begin_handshake_request;
  impl->base.begin_handshake_reply = &test_begin_handshake_reply;
  impl->base.process_handshake = &test_process_handshake;
  impl->base.get_shared_secret = &test_get_shared_secret;
  impl->base.get_authenticated_peer_credential_token = &test_get_authenticated_peer_credential_token;
  impl->base.set_listener = &test_set_listener;
  impl->base.return_identity_token = &test_return_identity_token;
  impl->base.return_identity_status_token = &test_return_identity_status_token;
  impl->base.return_authenticated_peer_credential_token = &test_return_authenticated_peer_credential_token;
  impl->base.return_handshake_handle = &test_return_handshake_handle;
  impl->base.return_identity_handle = &test_return_identity_handle;
  impl->base.return_sharedsecret_handle = &test_return_sharedsecret_handle;
  return impl;
}

int32_t init_test_authentication_all_ok(const char *argument, void **context)
{
  DDSRT_UNUSED_ARG(argument);
  DDSRT_UNUSED_ARG(context);
  struct dds_security_authentication_impl *impl = init_test_authentication_common();
  impl->mode = PLUGIN_MODE_ALL_OK;
  *context = impl;
  return 0;
}

int32_t finalize_test_authentication_all_ok(void *context)
{
  assert(((struct dds_security_authentication_impl *)context)->mode == PLUGIN_MODE_ALL_OK);
  ddsrt_free(context);
  return 0;
}

int32_t init_test_authentication_missing_func(const char *argument, void **context)
{
  DDSRT_UNUSED_ARG(argument);
  DDSRT_UNUSED_ARG(context);
  struct dds_security_authentication_impl *impl = init_test_authentication_common();
  impl->base.get_shared_secret = NULL;
  impl->mode = PLUGIN_MODE_MISSING_FUNC;
  *context = impl;
  return 0;
}

int32_t finalize_test_authentication_missing_func(void *context)
{
  assert(((struct dds_security_authentication_impl *)context)->mode == PLUGIN_MODE_MISSING_FUNC);
  ddsrt_free(context);
  return 0;
}

int32_t init_test_authentication_init_error(const char *argument, void **context)
{
  DDSRT_UNUSED_ARG(argument);
  DDSRT_UNUSED_ARG(context);
  return 1;
}

int32_t finalize_test_authentication_init_error(void *context)
{
  DDSRT_UNUSED_ARG(context);
  return 0;
}

int32_t init_test_authentication_wrapped(const char *argument, void **context)
{
  int32_t ret;
  struct dds_security_authentication_impl *impl = init_test_authentication_common();
  impl->mode = PLUGIN_MODE_WRAPPED;

  init_message_queue(&impl->msg_queue);
  struct thread_state1 * const ts1 = lookup_thread_state ();
  struct ddsi_domaingv const * const gv = ddsrt_atomic_ldvoidp (&ts1->gv);
  impl->gv = gv;

  ret = init_authentication(argument, (void **)&impl->instance);

  auth_impl_count++;
  auth_impl = ddsrt_realloc(auth_impl, auth_impl_count * sizeof(*auth_impl));
  auth_impl[auth_impl_count - 1] = impl;

  *context = impl;
  return ret;
}

int32_t finalize_test_authentication_wrapped(void *context)
{
  int32_t ret;
  struct dds_security_authentication_impl *impl = context;
  assert(impl->mode == PLUGIN_MODE_WRAPPED);
  deinit_message_queue(&impl->msg_queue);
  ret = finalize_authentication(impl->instance);
  ddsrt_free(context);
  auth_impl_count--;
  return ret;
}

