/*
 * Copyright(c) 2006 to 2018 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdio.h>
#include <stdbool.h>

#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/misc.h"

#include "CUnit/CUnit.h"
#include "CUnit/Test.h"
#include "dds/dds.h"
#include "dds__types.h"
#include "dds__entity.h"
#include "dds/security/core/dds_security_fsm.h"

#define CHECK_BIT(var, pos) ((var) & (1<<(pos)))

#define FSM_AUTH_ARG 10

#define DB_TC_PRINT_DEBUG  (true)

static dds_entity_t g_participant = 0;
static ddsrt_mutex_t g_lock;
static struct dds_security_fsm_control *g_fsm_control = NULL;
static const dds_duration_t msec100 = DDS_MSECS(100);

//static int fsm_arg = FSM_AUTH_ARG;

#define DO_SIMPLE(name, var, bit) static void name(struct dds_security_fsm *fsm, void *arg) { \
  DDSRT_UNUSED_ARG(fsm); \
  DDSRT_UNUSED_ARG(arg); \
  if (DB_TC_PRINT_DEBUG) \
    printf("Transition %s\n", __FUNCTION__); \
  ddsrt_mutex_lock(&g_lock); \
  visited_##var |= 1u << (bit); \
  ddsrt_mutex_unlock(&g_lock); \
}


/**********************************************************************
 * Authentication State Machine properties and methods
 **********************************************************************/

typedef enum {
    VALIDATION_PENDING_RETRY,
    VALIDATION_FAILED,
    VALIDATION_OK,
    VALIDATION_OK_FINAL_MESSAGE,
    VALIDATION_PENDING_HANDSHAKE_MESSAGE,
    VALIDATION_PENDING_HANDSHAKE_REQUEST,
    PluginReturn_MAX
} PluginReturn;

static struct dds_security_fsm *fsm_auth;
static uint32_t visited_auth = 0;
static uint32_t correct_fsm = 0;
static uint32_t correct_arg = 0;
static int validate_remote_identity_first = 1;
static int begin_handshake_reply_first = 1;


static PluginReturn validate_remote_identity(void)
{
  if (DB_TC_PRINT_DEBUG) {
    printf("validate_remote_identity - %d\n", validate_remote_identity_first);
  }
  if (validate_remote_identity_first) {
    validate_remote_identity_first = 0;
    return VALIDATION_PENDING_RETRY;
  }
  return VALIDATION_PENDING_HANDSHAKE_MESSAGE;
}

static PluginReturn begin_handshake_reply(void)
{
  if (DB_TC_PRINT_DEBUG) {
    printf("begin_handshake_reply - %d\n", begin_handshake_reply_first);
  }
  if (begin_handshake_reply_first) {
    begin_handshake_reply_first = 0;
    return VALIDATION_PENDING_RETRY;
  }
  return VALIDATION_OK_FINAL_MESSAGE;
}

static PluginReturn get_shared_secret(void)
{
  return VALIDATION_OK;
}

/* State actions. */
static void fsm_validate_remote_identity(struct dds_security_fsm *fsm, void *arg)
{
  PluginReturn ret;

  DDSRT_UNUSED_ARG(arg);

  ret = validate_remote_identity();

  if (DB_TC_PRINT_DEBUG) {
    printf("[%p] State %s (ret %d)\n", fsm, __FUNCTION__, (int) ret);
  }

  dds_security_fsm_dispatch(fsm, (int32_t) ret, false);
}

static void fsm_begin_handshake_reply(struct dds_security_fsm *fsm, void *arg)
{
  PluginReturn ret;

  DDSRT_UNUSED_ARG(arg);

  ret = begin_handshake_reply();
  if (ret == VALIDATION_OK_FINAL_MESSAGE) {
    ret = get_shared_secret();
  }

  if (DB_TC_PRINT_DEBUG) {
    printf("[%p] State %s (ret %d)\n", fsm, __FUNCTION__, (int) ret);
  }

  dds_security_fsm_dispatch(fsm, (int32_t) ret, false);
}

/* A few states from the handshake state-machine. */
static dds_security_fsm_state StateValidateRemoteIdentity = {fsm_validate_remote_identity, 0};
static dds_security_fsm_state StateValRemIdentityRetryWait = {NULL, 100000000};
static dds_security_fsm_state StateHandshakeInitMessageWait = {NULL, 0};
static dds_security_fsm_state StateBeginHandshakeReply = {fsm_begin_handshake_reply, 0};
static dds_security_fsm_state StateBeginHsReplyWait = {NULL, 100000000};

static void a(struct dds_security_fsm *fsm, void *arg)
{
  int *fsm_arg;

  if (DB_TC_PRINT_DEBUG) {
    printf("[%p] Transition %s\n", fsm, __FUNCTION__);
  }

  ddsrt_mutex_lock (&g_lock);
  if (arg != NULL) {
    fsm_arg = (int *) arg;

    if (*fsm_arg == FSM_AUTH_ARG) {
      correct_arg = 1;
    } else {
      correct_arg = 0;
    }
  }

  if (fsm == fsm_auth) {
    correct_fsm = 1;
  } else {
    correct_fsm = 0;
  }
  visited_auth |= 1u << 0;
  ddsrt_mutex_unlock (&g_lock);
}

DO_SIMPLE(b, auth, 1)
DO_SIMPLE(c, auth, 2)
DO_SIMPLE(d, auth, 3)
DO_SIMPLE(e, auth, 4)
DO_SIMPLE(f, auth, 5)
DO_SIMPLE(g, auth, 6)
DO_SIMPLE(h, auth, 7)

#define SHM_MSG_RECEIVED (PluginReturn_MAX + 1)

/*
 * .--.
 * |##|--------------------------------------.
 * '--'       a()                            v
 *                 .----------------------------------------------------.
 *                 |            StateValidateRemoteIdentity             |
 *                 |----------------------------------------------------|
 *         .------>| fsm_validate_remote_identity()                     |
 *         |       |    - dispatch VALIDATION_PENDING_RETRY             |
 *    100ms|       |    - dispatch VALIDATION_PENDING_HANDSHAKE_MESSAGE |
 *    d()  |       '----------------------------------------------------'
 *         |          VALIDATION_PENDING_RETRY|  | VALIDATION_PENDING_HANDSHAKE_MESSAGE
 *         |          b()                     |  | c()
 *         |                                  |  |
 * .------------------------------.           |  |       .-------------------------------.
 * | StateValRemIdentityRetryWait |           |  |       | StateHandshakeInitMessageWait |
 * |------------------------------|<----------'  '------>|-------------------------------|
 * '------------------------------'                      '-------------------------------'
 *                                                SHM_MSG_RECEIVED  |
 *                                                e()               |
 *                                                                  v
 *                                      .----------------------------------------.
 *          VALIDATION_PENDING_RETRY    |        StateBeginHandshakeReply        |
 *          f()                         |----------------------------------------|
 *            .-------------------------| fsm_begin_handshake_reply()            |
 *            |                         |    - dispatch VALIDATION_PENDING_RETRY |
 *            v                         |    - dispatch VALIDATION_OK            |
 * .-----------------------.    100ms   '----------------------------------------'
 * | StateBeginHsReplyWait |    h()                ^        VALIDATION_OK |
 * |-----------------------|-----------------------'        g()           |
 * '-----------------------'                                              v
 *                                                                       .-.
 *                                                                       '-'
 */
static dds_security_fsm_transition HandshakeTransistions[] = {
    {NULL,                           DDS_SECURITY_FSM_EVENT_AUTO,          a, &StateValidateRemoteIdentity}, // NULL state is the start state
    {&StateValidateRemoteIdentity,   VALIDATION_PENDING_RETRY,             b, &StateValRemIdentityRetryWait},
    {&StateValidateRemoteIdentity,   VALIDATION_PENDING_HANDSHAKE_MESSAGE, c, &StateHandshakeInitMessageWait},
    {&StateValRemIdentityRetryWait,  DDS_SECURITY_FSM_EVENT_TIMEOUT,       d, &StateValidateRemoteIdentity},
    {&StateHandshakeInitMessageWait, SHM_MSG_RECEIVED,                     e, &StateBeginHandshakeReply},
    {&StateBeginHandshakeReply,      VALIDATION_PENDING_RETRY,             f, &StateBeginHsReplyWait},
    {&StateBeginHandshakeReply,      VALIDATION_OK,                        g, NULL}, // Reaching NULL means end of state-diagram
    {&StateBeginHsReplyWait,         DDS_SECURITY_FSM_EVENT_TIMEOUT,       h, &StateBeginHandshakeReply}
};
static const uint32_t HandshakeTransistionsSize = sizeof(HandshakeTransistions)/sizeof(HandshakeTransistions[0]);


/**********************************************************************
 * Example State Machine properties and methods
 **********************************************************************/

typedef enum {
    eventX, eventY, eventZ,
} test_events;

static struct dds_security_fsm *fsm_test;
static uint32_t visited_test = 0;
static int do_stuff_counter = 0;
static int do_other_stuff_counter = 0;

DO_SIMPLE(doStart, test, 0)
DO_SIMPLE(doRestart, test, 1)
DO_SIMPLE(doEventStuff, test, 4)

static void doStuff(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(fsm);
  DDSRT_UNUSED_ARG(arg);

  if (DB_TC_PRINT_DEBUG) {
    printf("Transition %s - %d\n", __FUNCTION__, do_stuff_counter);
  }
  ddsrt_mutex_lock (&g_lock);
  visited_test |= 1u << 2;
  ddsrt_mutex_unlock (&g_lock);

  if (do_stuff_counter < 2) {
    dds_security_fsm_dispatch(fsm, eventZ, false);
  } else if (do_stuff_counter == 2) {
    dds_security_fsm_dispatch(fsm, eventY, false);
  }
  ++do_stuff_counter;
}

static void doOtherStuff(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(fsm);
  DDSRT_UNUSED_ARG(arg);

  if (DB_TC_PRINT_DEBUG) {
    printf("Transition %s - %d\n", __FUNCTION__, do_other_stuff_counter);
  }
  ddsrt_mutex_lock (&g_lock);
  visited_test |= 1u << 3;
  ddsrt_mutex_unlock (&g_lock);

  if (do_other_stuff_counter == 0) {
    dds_security_fsm_dispatch(fsm, DDS_SECURITY_FSM_EVENT_AUTO, false);
  }

  if (do_other_stuff_counter == 1) {
    dds_security_fsm_dispatch(fsm, eventY, false);
  } else if (do_other_stuff_counter == 2) {
    dds_security_fsm_dispatch(fsm, eventX, false);
  }
  ++do_other_stuff_counter;
}

static dds_security_fsm_state StateA = {doStuff,      0};
static dds_security_fsm_state StateB = {doStuff,      100000000};
static dds_security_fsm_state StateC = {NULL,         0};
static dds_security_fsm_state StateD = {doOtherStuff, 0};

static dds_security_fsm_transition Transitions[] = {
    {NULL,    DDS_SECURITY_FSM_EVENT_AUTO, doStart,      &StateA}, // NULL state is the start state
    {&StateA, eventZ,                      NULL,         &StateB},
    {&StateA, eventY,                      doOtherStuff, &StateC},
    {&StateB, eventX,                      NULL,         NULL}, // Reaching NULL means end of state-diagram
    {&StateB, eventZ,                      doRestart,    &StateA},
    {&StateC, DDS_SECURITY_FSM_EVENT_AUTO, doEventStuff, &StateD},
    {&StateD, eventY,                      doEventStuff, &StateD},
    {&StateD, eventX,                      doStuff,      NULL}, // Reaching NULL means end of sttimeoutate-diagram
};
static const uint32_t TransitionsSize = sizeof(Transitions)/sizeof(Transitions[0]);


/**********************************************************************
 * Timeout State Machine properties and methods
 **********************************************************************/

typedef enum {
    eventToTimeout, eventToInterupt, eventToEnd,
} timeout_events;

struct fsm_timeout_arg {
  int id;
};

static struct dds_security_fsm *fsm_timeout;
static uint32_t visited_timeout = 0;
static uint32_t correct_fsm_timeout = 0;
static uint32_t correct_arg_timeout = 0;
static struct fsm_timeout_arg fsm_arg = { .id = FSM_AUTH_ARG };

DO_SIMPLE(doInterrupt, timeout, 0)
DO_SIMPLE(TimeoutCallback2, timeout, 3)

static void doTimeout(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(arg);

  if (DB_TC_PRINT_DEBUG) {
    printf("Transition >>>> %s\n", __FUNCTION__);
  }
  ddsrt_mutex_lock (&g_lock);
  visited_timeout |= 1u << 1;
  ddsrt_mutex_unlock (&g_lock);

  if (DB_TC_PRINT_DEBUG) {
    printf("Transition <<<< %s\n", __FUNCTION__);
  }

  dds_security_fsm_dispatch(fsm, eventToTimeout, false);
}

static void TimeoutCallback(struct dds_security_fsm *fsm, void *arg)
{
  struct fsm_timeout_arg *farg = arg;

  if (DB_TC_PRINT_DEBUG) {
    printf("TimeoutCallback\n");
  }

  ddsrt_mutex_lock (&g_lock);
  visited_timeout |= 1u << 2;

  if (farg != NULL) {
    if (farg->id == FSM_AUTH_ARG) {
      correct_arg_timeout = 1;
    } else {
      correct_arg_timeout = 0;
    }
  }
  if (fsm == fsm_timeout) {
    correct_fsm_timeout = 1;
  } else {
    correct_fsm_timeout = 0;
  }
  ddsrt_mutex_unlock (&g_lock);
}

static dds_security_fsm_state StateInitial     = {doTimeout,  0};
static dds_security_fsm_state StateWaitTimeout = {NULL, DDS_SECS(4)};
static dds_security_fsm_state StateInterupt    = {doInterrupt, 0};


static const dds_security_fsm_transition TimeoutTransitions[] = {
    {NULL,              DDS_SECURITY_FSM_EVENT_AUTO,    NULL, &StateInitial},  // NULL state is the start state
    {&StateInitial,     eventToTimeout,                 NULL, &StateWaitTimeout},
    {&StateWaitTimeout, DDS_SECURITY_FSM_EVENT_TIMEOUT, NULL, &StateInterupt},
    {&StateWaitTimeout, eventToInterupt,                NULL, &StateInterupt},
    {&StateInterupt,    eventToEnd,                     NULL, NULL},           // Reaching NULL means end of state-diagram
};
static const uint32_t TimeoutTransitionsSize = sizeof(TimeoutTransitions)/sizeof(TimeoutTransitions[0]);


/**********************************************************************
 * Parallel Timeout State Machines properties and methods
 **********************************************************************/

static struct dds_security_fsm *fsm_timeout1;
static struct dds_security_fsm *fsm_timeout2;
static struct dds_security_fsm *fsm_timeout3;

static dds_time_t time0 = 0;
static dds_time_t time1 = 0;
static dds_time_t time2 = 0;
static dds_time_t time3 = 0;

static void StateParTime1(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(fsm);
  DDSRT_UNUSED_ARG(arg);
  time1 = dds_time();
}

static void StateParTime2(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(fsm);
  DDSRT_UNUSED_ARG(arg);
  time2 = dds_time();
}

static void StateParTime3(struct dds_security_fsm *fsm, void *arg)
{
  DDSRT_UNUSED_ARG(fsm);
  DDSRT_UNUSED_ARG(arg);
  time3 = dds_time();
}

static dds_security_fsm_state StateParTimeout1 = {NULL, DDS_SECS(1)};
static dds_security_fsm_state StateParTimeout2 = {NULL, DDS_SECS(2)};
static dds_security_fsm_state StateParTimeout3 = {NULL, DDS_SECS(1)};

static dds_security_fsm_transition ParallelTimeoutTransitions_1[] = {
    {NULL,              DDS_SECURITY_FSM_EVENT_AUTO,    NULL,           &StateParTimeout1}, // NULL state is the startfsm_control_thread state
    {&StateParTimeout1, DDS_SECURITY_FSM_EVENT_TIMEOUT, &StateParTime1, NULL},              // Reaching NULL means end of state-diagram
};
static const uint32_t ParallelTimeoutTransitionsSize_1 = sizeof(ParallelTimeoutTransitions_1) / sizeof(ParallelTimeoutTransitions_1[0]);

static dds_security_fsm_transition ParallelTimeoutTransitions_2[] = {
    {NULL,              DDS_SECURITY_FSM_EVENT_AUTO,    NULL,           &StateParTimeout2}, // NULL state is the start state
    {&StateParTimeout2, DDS_SECURITY_FSM_EVENT_TIMEOUT, &StateParTime2, NULL},              // Reaching NULL means end of state-diagram
};
static const uint32_t ParallelTimeoutTransitionsSize_2 = sizeof(ParallelTimeoutTransitions_2) / sizeof(ParallelTimeoutTransitions_2[0]);

static dds_security_fsm_transition ParallelTimeoutTransitions_3[] = {
    {NULL,              DDS_SECURITY_FSM_EVENT_AUTO,    NULL,           &StateParTimeout3}, // NULL state is the start state
    {&StateParTimeout3, DDS_SECURITY_FSM_EVENT_TIMEOUT, &StateParTime3, NULL},              // Reaching NULL means end of state-diagram
};
static const uint32_t ParallelTimeoutTransitionsSize_3 = sizeof(ParallelTimeoutTransitions_3) / sizeof(ParallelTimeoutTransitions_3[0]);

static void fsm_control_init(void)
{
  dds_return_t rc;
  struct dds_entity *e;

  g_participant = dds_create_participant(DDS_DOMAIN_DEFAULT, NULL, NULL);
  CU_ASSERT_FATAL(g_participant > 0);

  ddsrt_mutex_init (&g_lock);

  rc = dds_entity_pin(g_participant, &e);
  CU_ASSERT_FATAL(rc == 0);

  g_fsm_control = dds_security_fsm_control_create (&e->m_domain->gv);
  CU_ASSERT_FATAL (g_fsm_control != NULL);

  dds_entity_unpin (e);

  rc = dds_security_fsm_control_start (g_fsm_control, NULL);
  CU_ASSERT_FATAL(rc == 0);
}

static void fsm_control_fini(void)
{
  dds_security_fsm_control_stop(g_fsm_control);
  dds_security_fsm_control_free(g_fsm_control);
  ddsrt_mutex_destroy (&g_lock);

  dds_delete(g_participant);
}

CU_Test(ddssec_fsm, create, .init = fsm_control_init, .fini = fsm_control_fini)
{
  dds_time_t delay30 = DDS_SECS(30);
  int timeout;

  /*
   * Test single running state machine
   * Check creation of a single State Machine
   */
  fsm_auth = dds_security_fsm_create(g_fsm_control, HandshakeTransistions, HandshakeTransistionsSize, &fsm_arg);
  CU_ASSERT_FATAL(fsm_auth != NULL)

  // set a delay that doesn't expire. Should be terminate when fsm is freed.
  dds_security_fsm_set_timeout(fsm_auth, TimeoutCallback, delay30);
  dds_security_fsm_start(fsm_auth);

  /**
   * Check the result of one running State Machine
   */

  // Wait for the last state to occur
  timeout = 100; /* 10 sec */
  while ((dds_security_fsm_current_state(fsm_auth) != &StateHandshakeInitMessageWait) && (timeout > 0)) {
    dds_sleepfor(msec100);
    timeout--;
  }
  CU_ASSERT(timeout > 0);
  dds_security_fsm_dispatch(fsm_auth, SHM_MSG_RECEIVED, false);

  timeout = 100; /* 10 sec */
  while ((dds_security_fsm_current_state(fsm_auth) != NULL) && (timeout > 0)) {
    dds_sleepfor(msec100);
    timeout--;
  }
  CU_ASSERT(timeout > 0);

  ddsrt_mutex_lock (&g_lock);
  CU_ASSERT(visited_auth == 0xff);
  ddsrt_mutex_unlock (&g_lock);

  /*
   * "Check correct callback parameter passing (from fsm to user defined methods) ");
   */
  CU_ASSERT(correct_arg && correct_fsm);
  dds_security_fsm_free(fsm_auth);

  /* Check whether timeout callback has NOT been invoked */
  ddsrt_mutex_lock (&g_lock);
  CU_ASSERT(visited_timeout == 0);
  ddsrt_mutex_unlock (&g_lock);
}

/*
 * Test multiple (2) running state machines
 */
CU_Test(ddssec_fsm, multiple, .init = fsm_control_init, .fini = fsm_control_fini)
{
  int timeout;

  /*Check creation of multiple (2) State Machines*/
  validate_remote_identity_first = 0;
  begin_handshake_reply_first = 0;
  visited_auth = 0;
  visited_test = 0;

  fsm_auth = dds_security_fsm_create(g_fsm_control, HandshakeTransistions, HandshakeTransistionsSize, NULL);
  CU_ASSERT_FATAL(fsm_auth != NULL);

  fsm_test = dds_security_fsm_create(g_fsm_control, Transitions, TransitionsSize, NULL);
  CU_ASSERT_FATAL(fsm_test != NULL);

  dds_security_fsm_start(fsm_auth);
  dds_security_fsm_start(fsm_test);

  /* Check the results of multiple running State Machines */

  /* Wait for the last state to occur */
  timeout = 100; /* 10 sec */
  while ((dds_security_fsm_current_state(fsm_auth) != &StateHandshakeInitMessageWait) && (timeout > 0)) {
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
  }
  CU_ASSERT_FATAL(timeout > 0);

  timeout = 100; /* 10 sec */
  dds_security_fsm_dispatch(fsm_auth, SHM_MSG_RECEIVED, false);
  while ((dds_security_fsm_current_state(fsm_auth) != NULL) && (timeout > 0)) {
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
  }
  CU_ASSERT_FATAL(timeout > 0);

  // not all bits are set since we're running the state machine a second time
  ddsrt_mutex_lock (&g_lock);
  CU_ASSERT_FATAL(visited_auth == 0x55);
  ddsrt_mutex_unlock (&g_lock);

  /* Wait for the last state to occur */
  timeout = 100; /* 10 sec */
  while ((dds_security_fsm_current_state(fsm_test) != NULL) && timeout > 0) {
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
  }
  CU_ASSERT_FATAL(timeout > 0);

  ddsrt_mutex_lock (&g_lock);
  CU_ASSERT(visited_test == 0x1f);
  ddsrt_mutex_unlock (&g_lock);

  dds_security_fsm_free(fsm_auth);
  dds_security_fsm_free(fsm_test);

}

/**
 * Check creation of State Machine for timeout purposes
 */
CU_Test(ddssec_fsm, timeout, .init = fsm_control_init, .fini = fsm_control_fini)
{
  dds_time_t delay1 = DDS_SECS(1);
  int timeout;

  visited_timeout = 0;

  /*
   * Test timeout monitoring of state machines
   */
  fsm_timeout = dds_security_fsm_create(g_fsm_control, TimeoutTransitions, TimeoutTransitionsSize, &fsm_arg);
  CU_ASSERT(fsm_timeout != NULL);

  dds_security_fsm_set_timeout(fsm_timeout, TimeoutCallback, delay1);
  dds_security_fsm_start(fsm_timeout);

  /*Check the result of the running State Machine for timeout purposes*/

  // Wait for the last state to occur
  timeout = 100; /* 10 sec */
  ddsrt_mutex_lock (&g_lock);
  while (visited_timeout != 0x7 && (timeout > 0)) {
    ddsrt_mutex_unlock (&g_lock);
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
    ddsrt_mutex_lock (&g_lock);
  }
  CU_ASSERT(timeout > 0);
  CU_ASSERT(visited_timeout == 0x7);
  CU_ASSERT(correct_arg_timeout && correct_fsm_timeout);
  ddsrt_mutex_unlock (&g_lock);

  dds_security_fsm_free(fsm_timeout);
}

/**
 * Check the double global timeout
 */
CU_Test(ddssec_fsm, double_timeout, .init = fsm_control_init, .fini = fsm_control_fini)
{
  dds_time_t delay1 = DDS_SECS(1);
  dds_time_t delay2 = DDS_SECS(2);
  int timeout;

  visited_timeout = 0;
  fsm_timeout = dds_security_fsm_create(g_fsm_control, TimeoutTransitions, TimeoutTransitionsSize, &fsm_arg);
  CU_ASSERT(fsm_timeout != NULL);

  fsm_timeout2 = dds_security_fsm_create(g_fsm_control, TimeoutTransitions, TimeoutTransitionsSize, &fsm_arg);
  CU_ASSERT(fsm_timeout2 != NULL);

  dds_security_fsm_set_timeout(fsm_timeout, TimeoutCallback, delay1);
  dds_security_fsm_set_timeout(fsm_timeout2, TimeoutCallback2, delay2);
  dds_security_fsm_start(fsm_timeout);
  dds_security_fsm_start(fsm_timeout2);
  timeout = 100; /* 10 sec */
  ddsrt_mutex_lock (&g_lock);
  while (visited_timeout != 0xf && (timeout > 0)) {
    ddsrt_mutex_unlock (&g_lock);
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
    ddsrt_mutex_lock (&g_lock);
  }
  CU_ASSERT(visited_timeout == 0xf);
  ddsrt_mutex_unlock (&g_lock);
  dds_security_fsm_free(fsm_timeout);
  dds_security_fsm_free(fsm_timeout2);
}

/**
 * Check parallel state timeouts
 */
CU_Test(ddssec_fsm, parallel_timeout, .init = fsm_control_init, .fini = fsm_control_fini)
{
  dds_duration_t delta1;
  dds_duration_t delta2;
  dds_duration_t delta3;
  int timeout;

  visited_timeout = 0;

  fsm_timeout1 = dds_security_fsm_create(g_fsm_control, ParallelTimeoutTransitions_1, ParallelTimeoutTransitionsSize_1, &fsm_arg);
  CU_ASSERT_FATAL(fsm_timeout1 != NULL);

  fsm_timeout2 = dds_security_fsm_create(g_fsm_control, ParallelTimeoutTransitions_2, ParallelTimeoutTransitionsSize_2, &fsm_arg);
  CU_ASSERT_FATAL(fsm_timeout2 != NULL);

  fsm_timeout3 = dds_security_fsm_create(g_fsm_control, ParallelTimeoutTransitions_3, ParallelTimeoutTransitionsSize_3, &fsm_arg);
  CU_ASSERT_FATAL(fsm_timeout3 != NULL);

  time0 = dds_time();
  dds_security_fsm_start(fsm_timeout1);
  dds_security_fsm_start(fsm_timeout2);
  dds_security_fsm_start(fsm_timeout3);

  /* Wait for both to end. */
  timeout = 300; /* 10 sec */
  /* First, they have to be started. */
  while (((dds_security_fsm_current_state(fsm_timeout1) == NULL)
          || (dds_security_fsm_current_state(fsm_timeout2) == NULL)
          || (dds_security_fsm_current_state(fsm_timeout3) == NULL)) && (timeout > 0)) {
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
  }

  /* Then, they have to have ended. */
  while (((dds_security_fsm_current_state(fsm_timeout1) != NULL)
          || (dds_security_fsm_current_state(fsm_timeout2) != NULL)
          || (dds_security_fsm_current_state(fsm_timeout3) != NULL)) && (timeout > 0)) {
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
  }

  /*
   * There should be about 1 second difference between all times:
   *      time1 = time0 + 1
   *      time2 = time0 + 2
   *      time3 = time0 + 1
   */
  delta1 = time1 - time0;
  delta2 = time2 - time0;
  delta3 = time3 - time0;
  printf("Time0 %" PRId64 "\n", time0);
  printf("Time1 %" PRId64 "\n", time1);
  printf("Time2 %" PRId64 "\n", time2);
  printf("Time3 %" PRId64 "\n", time3);
  printf("Delta1 %" PRId64 "\n", delta1);
  printf("Delta2 %" PRId64 "\n", delta2);
  printf("Delta3 %" PRId64 "\n", delta3);
  CU_ASSERT(delta1 > 750 * DDS_NSECS_IN_MSEC);
  CU_ASSERT(delta1 < 1250 * DDS_NSECS_IN_MSEC);
  CU_ASSERT(delta2 > 1750 * DDS_NSECS_IN_MSEC);
  CU_ASSERT(delta2 < 2250 * DDS_NSECS_IN_MSEC);
  CU_ASSERT(delta3 > 750 * DDS_NSECS_IN_MSEC);
  CU_ASSERT(delta3 < 1250 * DDS_NSECS_IN_MSEC);

  dds_security_fsm_free(fsm_timeout1);
  dds_security_fsm_free(fsm_timeout2);
  dds_security_fsm_free(fsm_timeout3);

}

/**
 * Delete with event timeout
 */
CU_Test(ddssec_fsm, delete_with_timeout, .init = fsm_control_init, .fini = fsm_control_fini)
{
  int timeout;

  fsm_timeout = dds_security_fsm_create(g_fsm_control, TimeoutTransitions, TimeoutTransitionsSize, &fsm_arg);
  CU_ASSERT (fsm_timeout != NULL)

  visited_timeout = 0;
  dds_security_fsm_start(fsm_timeout);

  /* Wait until we're in the timeout function. */
  timeout = 100; /* 10 sec */
  ddsrt_mutex_lock (&g_lock);
  while ((visited_timeout == 0) && (timeout > 0)) {
    ddsrt_mutex_unlock (&g_lock);
    dds_sleepfor(100 * DDS_NSECS_IN_MSEC);
    timeout--;
    ddsrt_mutex_lock (&g_lock);
  }
  ddsrt_mutex_unlock (&g_lock);

  dds_security_fsm_free(fsm_timeout);
}

