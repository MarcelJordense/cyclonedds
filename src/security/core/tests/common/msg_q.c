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
#include "msg_q.h"

void insert_message(struct message_queue *queue, struct message *msg)
{
  ddsrt_mutex_lock(&queue->lock);
  if (!queue->head)
    queue->head = msg;
  else
    queue->tail->next = msg;
  queue->tail = msg;

  ddsrt_cond_signal(&queue->cond);
  ddsrt_mutex_unlock(&queue->lock);
}

void add_message(struct message_queue *queue, message_kind_t kind, DDS_Security_IdentityHandle lidHandle, DDS_Security_IdentityHandle ridHandle, DDS_Security_IdentityHandle hsHandle,
    const DDS_Security_GUID_t *lguid, const DDS_Security_GUID_t *rguid, DDS_Security_ValidationResult_t result,
    const DDS_Security_DataHolder *token, void *instance)
{
  struct message *msg = ddsrt_malloc(sizeof(*msg));
  memset(msg, 0, sizeof(*msg));
  msg->kind = kind;
  msg->lidHandle = lidHandle;
  msg->ridHandle = ridHandle;
  msg->hsHandle = hsHandle;
  msg->result = result;
  if (lguid)
    memcpy(&msg->lguid, lguid, sizeof(msg->lguid));
  if (rguid)
    memcpy(&msg->rguid, rguid, sizeof(msg->rguid));
  if (token)
    DDS_Security_DataHolder_copy(&msg->token, token);
  msg->instance = instance;

  insert_message(queue, msg);
}

void delete_message(struct message *msg)
{
  if (msg)
  {
    DDS_Security_DataHolder_deinit(&msg->token);
    ddsrt_free(msg);
  }
}

void init_message_queue(struct message_queue *queue)
{
  queue->head = NULL;
  queue->tail = NULL;
  ddsrt_mutex_init(&queue->lock);
  ddsrt_cond_init(&queue->cond);
}

void deinit_message_queue(struct message_queue *queue)
{
  struct message *msg = queue->head;
  while (msg)
  {
    queue->head = msg->next;
    delete_message(msg);
    msg = queue->head;
  }
  ddsrt_cond_destroy(&queue->cond);
  ddsrt_mutex_destroy(&queue->lock);
}

int message_matched(struct message *msg, message_kind_t kind, DDS_Security_IdentityHandle lidHandle, DDS_Security_IdentityHandle ridHandle, DDS_Security_IdentityHandle hsHandle)
{
  return msg->kind == kind &&
    (!lidHandle || msg->lidHandle == lidHandle) &&
    (!ridHandle || msg->ridHandle == ridHandle) &&
    (!hsHandle || msg->hsHandle == hsHandle);
}

struct message * take_message(struct message_queue *queue, message_kind_t kind, DDS_Security_IdentityHandle lidHandle, DDS_Security_IdentityHandle ridHandle, DDS_Security_IdentityHandle hsHandle, dds_duration_t timeout)
{
  struct message *msg = NULL, *cur, *prev;
  int r = 1;
  ddsrt_mutex_lock(&queue->lock);
  do
  {
    cur = queue->head;
    prev = NULL;
    while (cur && !msg)
    {
      if (message_matched(cur, kind, lidHandle, ridHandle, hsHandle))
      {
        msg = cur;
        if (prev)
          prev->next = msg->next;
        else
          queue->head = msg->next;
        if (queue->tail == msg)
          queue->tail = prev;
      }
      else
      {
        prev = cur;
        cur = cur->next;
      }
    }
    if (!msg)
    {
      if (!ddsrt_cond_waitfor(&queue->cond, &queue->lock, timeout))
        r = 0;
    }
  } while (r && !msg);

  ddsrt_mutex_unlock(&queue->lock);
  return msg;
}