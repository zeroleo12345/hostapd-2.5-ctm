# src/radius/radius_server.c
static struct radius_session * radius_server_get_new_session(struct radius_server_data *data, struct radius_client *client, struct radius_msg *msg, const char *from_addr)
	sess->eap = eap_server_sm_init(sess, &radius_server_eapol_cb, &eap_conf);	# 初始化下面的结构 struct eap_sm *sm

# src/eap_server/eap_server.c
struct eap_sm * eap_server_sm_init(void *eapol_ctx, const struct eapol_callbacks *eapol_cb, struct eap_config *conf)



# src/radius/radius_server.c
static int radius_server_request(struct radius_server_data *data, struct radius_msg *msg, struct sockaddr *from, struct radius_client *client, struct radius_session *force_sess)
    eap_server_sm_step(sess->eap);	# 调用EAP认证流程


# src/eap_server/eap_server.c
int eap_server_sm_step(struct eap_sm *sm)
{
	do {
		SM_STEP_RUN(EAP);       # EAP认证方法会话, Access-Accept 或者 Access-Reject 会返回到次此函数外层处理
	} while (sm->changed);
}


# src/eap_server/eap_server.c
SM_STEP(EAP)	# SM_STEP_RUN(EAP)  -> 定义方法: static void sm_EAP_Step(struct eap_sm *sm)
{
	if (sm->eap_if.eapRestart && sm->eap_if.portEnabled)
		SM_ENTER_GLOBAL(EAP, INITIALIZE);
	else if (!sm->eap_if.portEnabled)
		SM_ENTER_GLOBAL(EAP, DISABLED);
	else if (sm->num_rounds > EAP_MAX_AUTH_ROUNDS) {
		if (sm->num_rounds == EAP_MAX_AUTH_ROUNDS + 1) {
			wpa_printf(MSG_DEBUG, "EAP: more than %d "
				   "authentication rounds - abort",
				   EAP_MAX_AUTH_ROUNDS);
			sm->num_rounds++;
			SM_ENTER_GLOBAL(EAP, FAILURE);
		}
	} else switch (sm->EAP_state) {
		case EAP_INITIALIZE:		# 初始状态 1) SM_ENTER(EAP, INITIALIZE) -> SM_STATE(EAP, INITIALIZE) -> SM_ENTRY(EAP, INITIALIZE)
			if (sm->backend_auth) {
				if (!sm->rxResp)
					SM_ENTER(EAP, SELECT_ACTION);
				else if (sm->rxResp &&
					(sm->respMethod == EAP_TYPE_NAK ||
					(sm->respMethod == EAP_TYPE_EXPANDED &&
					sm->respVendor == EAP_VENDOR_IETF &&
					sm->respVendorMethod == EAP_TYPE_NAK)))
					SM_ENTER(EAP, NAK);
				else
					SM_ENTER(EAP, PICK_UP_METHOD);	# jump -> 2)
			} else {
				SM_ENTER(EAP, SELECT_ACTION);
			}
			break;
		case EAP_PICK_UP_METHOD:	# 状态 2) SM_ENTER(EAP, PICK_UP_METHOD) -> SM_STATE(EAP, PICK_UP_METHOD) -> SM_ENTRY(EAP, PICK_UP_METHOD)
			if (sm->currentMethod == EAP_TYPE_NONE) {
				SM_ENTER(EAP, SELECT_ACTION);
			} else {
				SM_ENTER(EAP, METHOD_RESPONSE);		# jump -> 3
			}
			break;
		case EAP_METHOD_RESPONSE:	# 状态 3) 
			/*
			* Note: Mechanism to allow EAP methods to wait while going
			* through pending processing is an extension to RFC 4137
			* which only defines the transits to SELECT_ACTION and
			* METHOD_REQUEST from this METHOD_RESPONSE state.
			*/
			if (sm->methodState == METHOD_END)
				SM_ENTER(EAP, SELECT_ACTION);
			else if (sm->method_pending == METHOD_PENDING_WAIT) {
				wpa_printf(MSG_DEBUG, "EAP: Method has pending "
					"processing - wait before proceeding to "
					"METHOD_REQUEST state");
			} else if (sm->method_pending == METHOD_PENDING_CONT) {
				wpa_printf(MSG_DEBUG, "EAP: Method has completed "
					"pending processing - reprocess pending "
					"EAP message");
				sm->method_pending = METHOD_PENDING_NONE;
				SM_ENTER(EAP, METHOD_RESPONSE);
			} else
				SM_ENTER(EAP, METHOD_REQUEST);
			break;
		case EAP_SELECT_ACTION:
			if (sm->decision == DECISION_FAILURE)
				SM_ENTER(EAP, FAILURE);
			else if (sm->decision == DECISION_SUCCESS)
				SM_ENTER(EAP, SUCCESS);
			else if (sm->decision == DECISION_PASSTHROUGH)
				SM_ENTER(EAP, INITIALIZE_PASSTHROUGH);
			else if (sm->decision == DECISION_INITIATE_REAUTH_START)
				SM_ENTER(EAP, INITIATE_REAUTH_START);
			else
				SM_ENTER(EAP, PROPOSE_METHOD);
			break;
		case EAP_IDLE:
			if (sm->eap_if.retransWhile == 0) {
				if (sm->try_initiate_reauth) {
					sm->try_initiate_reauth = FALSE;
					SM_ENTER(EAP, SELECT_ACTION);
				} else {
					SM_ENTER(EAP, RETRANSMIT);
				}
			} else if (sm->eap_if.eapResp)
				SM_ENTER(EAP, RECEIVED);
			break;
		case EAP_RETRANSMIT:
			if (sm->retransCount > sm->MaxRetrans)
				SM_ENTER(EAP, TIMEOUT_FAILURE);
			else
				SM_ENTER(EAP, IDLE);
			break;
		case EAP_RECEIVED:
			if (sm->rxResp && (sm->respId == sm->currentId) &&
				(sm->respMethod == EAP_TYPE_NAK ||
				(sm->respMethod == EAP_TYPE_EXPANDED &&
				sm->respVendor == EAP_VENDOR_IETF &&
				sm->respVendorMethod == EAP_TYPE_NAK))
				&& (sm->methodState == METHOD_PROPOSED))
				SM_ENTER(EAP, NAK);
			else if (sm->rxResp && (sm->respId == sm->currentId) &&
				((sm->respMethod == sm->currentMethod) ||
				(sm->respMethod == EAP_TYPE_EXPANDED &&
				sm->respVendor == EAP_VENDOR_IETF &&
				sm->respVendorMethod == sm->currentMethod)))
				SM_ENTER(EAP, INTEGRITY_CHECK);
			else {
				wpa_printf(MSG_DEBUG, "EAP: RECEIVED->DISCARD: "
					"rxResp=%d respId=%d currentId=%d "
					"respMethod=%d currentMethod=%d",
					sm->rxResp, sm->respId, sm->currentId,
					sm->respMethod, sm->currentMethod);
				eap_log_msg(sm, "Discard received EAP message");
				SM_ENTER(EAP, DISCARD);
			}
			break;
		case EAP_DISCARD:
			SM_ENTER(EAP, IDLE);
			break;
		case EAP_SEND_REQUEST:
			SM_ENTER(EAP, IDLE);
			break;
		case EAP_INTEGRITY_CHECK:
			if (sm->ignore)
				SM_ENTER(EAP, DISCARD);
			else
				SM_ENTER(EAP, METHOD_RESPONSE);
			break;
		case EAP_METHOD_REQUEST:
			if (sm->m == NULL) {
				/*
				* This transition is not mentioned in RFC 4137, but it
				* is needed to handle cleanly a case where EAP method
				* initialization fails.
				*/
				SM_ENTER(EAP, FAILURE);
				break;
			}
			SM_ENTER(EAP, SEND_REQUEST);
			if (sm->eap_if.eapNoReq && !sm->eap_if.eapReq) {
				/*
				* This transition is not mentioned in RFC 4137, but it
				* is needed to handle cleanly a case where EAP method
				* buildReq fails.
				*/
				wpa_printf(MSG_DEBUG,
					"EAP: Method did not return a request");
				SM_ENTER(EAP, FAILURE);
				break;
			}
			break;
		case EAP_PROPOSE_METHOD:
			/*
			* Note: Mechanism to allow EAP methods to wait while going
			* through pending processing is an extension to RFC 4137
			* which only defines the transit to METHOD_REQUEST from this
			* PROPOSE_METHOD state.
			*/
			if (sm->method_pending == METHOD_PENDING_WAIT) {
				wpa_printf(MSG_DEBUG, "EAP: Method has pending "
					"processing - wait before proceeding to "
					"METHOD_REQUEST state");
				if (sm->user_eap_method_index > 0)
					sm->user_eap_method_index--;
			} else if (sm->method_pending == METHOD_PENDING_CONT) {
				wpa_printf(MSG_DEBUG, "EAP: Method has completed "
					"pending processing - reprocess pending "
					"EAP message");
				sm->method_pending = METHOD_PENDING_NONE;
				SM_ENTER(EAP, PROPOSE_METHOD);
			} else
				SM_ENTER(EAP, METHOD_REQUEST);
			break;
		case EAP_NAK:
			SM_ENTER(EAP, SELECT_ACTION);
			break;
		case EAP_INITIATE_REAUTH_START:
			SM_ENTER(EAP, SEND_REQUEST);
			break;
		case EAP_INITIATE_RECEIVED:
			if (!sm->eap_server)
				SM_ENTER(EAP, SELECT_ACTION);
			break;
		case EAP_TIMEOUT_FAILURE:
			break;
		case EAP_FAILURE:
			break;
		case EAP_SUCCESS:
			break;

		case EAP_INITIALIZE_PASSTHROUGH:
			if (sm->currentId == -1)
				SM_ENTER(EAP, AAA_IDLE);
			else
				SM_ENTER(EAP, AAA_REQUEST);
			break;
		case EAP_IDLE2:
			if (sm->eap_if.eapResp)
				SM_ENTER(EAP, RECEIVED2);
			else if (sm->eap_if.retransWhile == 0)
				SM_ENTER(EAP, RETRANSMIT2);
			break;
		case EAP_RETRANSMIT2:
			if (sm->retransCount > sm->MaxRetrans)
				SM_ENTER(EAP, TIMEOUT_FAILURE2);
			else
				SM_ENTER(EAP, IDLE2);
			break;
		case EAP_RECEIVED2:
			if (sm->rxResp && (sm->respId == sm->currentId))
				SM_ENTER(EAP, AAA_REQUEST);
			else
				SM_ENTER(EAP, DISCARD2);
			break;
		case EAP_DISCARD2:
			SM_ENTER(EAP, IDLE2);
			break;
		case EAP_SEND_REQUEST2:
			SM_ENTER(EAP, IDLE2);
			break;
		case EAP_AAA_REQUEST:
			SM_ENTER(EAP, AAA_IDLE);
			break;
		case EAP_AAA_RESPONSE:
			SM_ENTER(EAP, SEND_REQUEST2);
			break;
		case EAP_AAA_IDLE:
			if (sm->eap_if.aaaFail)
				SM_ENTER(EAP, FAILURE2);
			else if (sm->eap_if.aaaSuccess)
				SM_ENTER(EAP, SUCCESS2);
			else if (sm->eap_if.aaaEapReq)
				SM_ENTER(EAP, AAA_RESPONSE);
			else if (sm->eap_if.aaaTimeout)
				SM_ENTER(EAP, TIMEOUT_FAILURE2);
			break;
		case EAP_TIMEOUT_FAILURE2:
			break;
		case EAP_FAILURE2:
			break;
		case EAP_SUCCESS2:
			break;
	}
}
