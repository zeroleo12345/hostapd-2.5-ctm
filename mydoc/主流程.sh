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


# src/eap_server/eap_server.c
SM_STATE(EAP, PICK_UP_METHOD)       # 由状态 EAP_INITIALIZE 来到 PICK_UP_METHOD
    sm->m = eap_server_get_eap_method(EAP_VENDOR_IETF, sm->currentMethod);     # 从全局变量 eap_methods 列表中取得相应的认证函数



# 其他资料
# RADIUS with MS-CHAPv2 Explanation
	https://stackoverflow.com/questions/30344085/radius-with-ms-chapv2-explanation


# Attributes for Support of MS-CHAP Version 2
	https://www.ietf.org/rfc/rfc2548.txt


struct eap_mschapv2_hdr {
	u8 op_code; /* MSCHAPV2_OP_* */
	u8 mschapv2_id; /* must be changed for challenges, but not for
			 * success/failure */
	u8 ms_length[2]; /* Note: misaligned; length - 5 */
	/* followed by data */
} STRUCT_PACKED;

struct eap_hdr {
	u8 code;
	u8 identifier;
	be16 length; /* including code and identifier; network byte order */
	/* followed by length-4 octets of data */
} STRUCT_PACKED;

# 服务端发送EAP拓展报文 eap_identity:
# 客户端响应 identity

# 服务端发送EAP拓展报文 eap_mschapv2_buildReq()		CHALLENGE:
eap_msg_alloc() 函数就是申请一块buffer, 装有EAP格式报文: code=REQUEST, Identity, Length, Type=EAP_TYPE_MSCHAPV2, Type-Data

eap_start = EapPeapPacket(code=EapPeapPacket.CODE_EAP_REQUEST, id=session.next_eap_id, flag_start=1, flag_version=1)
auth_challenge + server_id("hostapd")


EAP-MSCHAPV2: Challenge - hexdump(len=16): 2d ae 52 bf 07 d0 de 7b 28 c4 d8 d9 8f 87 da 6a
EAP-PEAP: Encrypting Phase 2 data - hexdump(len=33): EAP_CODE_REQUEST(01) + EAP_id(07) + 整个报文长度(00 21) + EAP_TYPE_MSCHAPV2报文(1a) + MSCHAPV2_OP_CHALLENGE(01) + 与EAP_id相同(07) + MSCHAPV2_OP 到结束的长度(00 1c) + 随机数长度固定值(10) + 16位随机chanllenge(2d ae 52 bf 07 d0 de 7b 28 c4 d8 d9 8f 87 da 6a) + server_id(68 6f 73 74 61 70 64)

# 客户端响应EAP拓展报文 eap_mschapv2_process_response()		CHALLENGE:
EAP-PEAP: Decrypted Phase 2 EAP - hexdump(len=67): EAP_CODE_RESPONSE(02) + EAP_id(07) +  长度(00 43) + MSCHAPV2 Type枚举值(1a) + MSCHAPV2_OP_RESPONSE(02) + 与EAP_id相同(07) + MSCHAPV2_OP 到结束的长度(00 3e) + 此字段后除username的长度(31) + 16位随机数与8位补0(16 79 ba 65 ad 16 7f 92 5c 74 c9 80 53 d6 fc 4c + 00 00 00 00 00 00 00 00) + NT-Response(72 0e 3d a8 8d bd f8 a9 e8 bd 1a 95 d9 5f 08 03 7e 10 db 9f 01 d4 a5 fc) + Flags(00) + 用户名testuser(74 65 73 74 75 73 65 72)
EAP-PEAP: received Phase 2: code=2 identifier=7 length=67
EAP-MSCHAPV2: Peer-Challenge - hexdump(len=16): 16 79 ba 65 ad 16 7f 92 5c 74 c9 80 53 d6 fc 4c
EAP-MSCHAPV2: Correct NT-Response
EAP-MSCHAPV2: Derived Master Key - hexdump(len=16): 20 a4 ef 4e 01 b7 7b e9 1d 2a 20 10 f5 ce 61 55

# 服务端发送 eap_mschapv2_buildReq()	SUCCESS_REQ:
EAP-MSCHAPV2: Success Request Message - hexdump_ascii(len=47):
     53 3d 37 43 36 39 38 34 37 38 39 44 34 39 44 30   S=7C6984789D49D0
     38 32 33 34 35 45 35 31 43 44 45 38 46 35 36 30   82345E51CDE8F560
     33 42 41 44 31 43 34 34 37 33 20 4d 3d 4f 4b      3BAD1C4473 M=OK
EAP-PEAP: Encrypting Phase 2 data - hexdump(len=56): EAP_CODE_REQUEST(01) + EAP_id(08) + 整个报文长度(00 38) + EAP_TYPE_MSCHAPV2报文(1a) + MSCHAPV2_OP_SUCCESS(03) + EAP_id减一(07) + MSCHAPV2_OP 到结束的长度(00 33) + S=(53 3d) + 40个字符:generate_authenticator_response_pwhash计算出来的哈希值再换成hex大写(37 43 36 39 38 34 37 38 39 44 34 39 44 30 38 32 33 34 35 45 35 31 43 44 45 38 46 35 36 30 33 42 41 44 31 43 34 34 37 33) + 空格(20) + M=OK(4d 3d 4f 4b)

# 服务端发送 EAP_SUCCESS
# 服务端发送 Access_Accept