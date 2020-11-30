enum {
    EAP_DISABLED, = 0
    EAP_INITIALIZE, = 1
    EAP_IDLE, = 2
    EAP_RECEIVED, = 3
    EAP_INTEGRITY_CHECK, = 4
    EAP_METHOD_RESPONSE, = 5
    EAP_METHOD_REQUEST, = 6
    EAP_PROPOSE_METHOD, = 7
    EAP_SELECT_ACTION, = 8
    EAP_SEND_REQUEST, = 9
    EAP_DISCARD, = 10
    EAP_NAK, = 11
    EAP_RETRANSMIT, = 12
    EAP_SUCCESS, = 13
    EAP_FAILURE, = 14
    EAP_TIMEOUT_FAILURE, = 15
    EAP_PICK_UP_METHOD, = 16
    EAP_INITIALIZE_PASSTHROUGH, = 17
    EAP_IDLE2, = 18
    EAP_RETRANSMIT2, = 19
    EAP_RECEIVED2, = 20
    EAP_DISCARD2, = 21
    EAP_SEND_REQUEST2, = 22
    EAP_AAA_REQUEST, = 23
    EAP_AAA_RESPONSE, = 24
    EAP_AAA_IDLE, = 25
    EAP_TIMEOUT_FAILURE2, = 26
    EAP_FAILURE2, = 27
    EAP_SUCCESS2, = 28
    EAP_INITIATE_REAUTH_START, = 29
    EAP_INITIATE_RECEIVED = 30
} EAP_state;

enum {
    START, = 0 
    PHASE1, = 1 
    PHASE1_ID2, = 2 
    PHASE2_START, = 3 
    PHASE2_ID, = 4
    PHASE2_METHOD, = 5 
    PHASE2_SOH, = 6 
    PHASE2_TLV, = 7 
    SUCCESS_REQ, = 8 
    FAILURE_REQ, = 9 
    SUCCESS, = 10
    FAILURE = 11
} state;


## hostapd日志
EAP: EAP entering state SELECT_ACTION
EAP: getDecision: another method available -> CONTINUE
EAP: EAP entering state PROPOSE_METHOD
EAP-PEAP: START -> PHASE1
EAP-PEAP: PHASE1 -> PHASE2_START
EAP-PEAP: PHASE2_START -> PHASE2_ID
EAP-PEAP: PHASE2_ID -> PHASE2_METHOD
EAP-PEAP: PHASE2_METHOD -> PHASE2_TLV
EAP-PEAP: PHASE2_TLV -> SUCCESS
EAP: getDecision: method succeeded -> SUCCESS
hostapd_interface_deinit_free: driver=0x56283bea1940 drv_priv=0x56283c781440 -> hapd_deinit


##
SM_STEP(EAP) sm->EAP_state = 1
SM_STEP(EAP) sm->EAP_state = 16
SM_STEP(EAP) sm->EAP_state = 5
SM_STEP(EAP) sm->EAP_state = 8
SM_STEP(EAP) sm->EAP_state = 7
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 11
SM_STEP(EAP) sm->EAP_state = 8
SM_STEP(EAP) sm->EAP_state = 7
eap_peap_buildReq() data->state = 0
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 1
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 1
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
SM_STEP(EAP) sm->EAP_state = 5
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 1
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 1
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 3
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 4
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 4
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 5
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 5
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 5
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 5
SM_STEP(EAP) sm->EAP_state = 5
eap_peap_buildReq() data->state = 8
SM_STEP(EAP) sm->EAP_state = 6
SM_STEP(EAP) sm->EAP_state = 9
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 2
SM_STEP(EAP) sm->EAP_state = 3
SM_STEP(EAP) sm->EAP_state = 4
eap_peap_process_msg() data->state = 8
SM_STEP(EAP) sm->EAP_state = 5
SM_STEP(EAP) sm->EAP_state = 8
SM_STEP(EAP) sm->EAP_state = 13
