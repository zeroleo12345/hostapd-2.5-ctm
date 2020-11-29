# eap_peap_buildReq() 状态流转
EAP: getDecision: another method available -> CONTINUE
EAP-PEAP: START -> PHASE1					# 1报文: eap_peap_start.
EAP-PEAP: PHASE1 -> PHASE2_START			# 2和3报文: server_hello和change_cipher_spec.
EAP-PEAP: PHASE2_START -> PHASE2_ID			# 4报文: peap_identity.
EAP-PEAP: PHASE2_ID -> PHASE2_METHOD		# 5报文: peap_password.
EAP-PEAP: PHASE2_METHOD -> SUCCESS_REQ		# 6报文: eap_peap_success.
EAP-PEAP: SUCCESS_REQ -> SUCCESS			# 7报文: access_accept.


# src/eap_server/eap_server.c
SM_STATE(EAP, METHOD_REQUEST)		# 在主流程中!!!
{
	SM_ENTRY(EAP, METHOD_REQUEST);

	if (sm->m == NULL) {
		wpa_printf(MSG_DEBUG, "EAP: method not initialized");
		return;
	}

	sm->currentId = eap_sm_nextId(sm, sm->currentId);
	wpa_printf(MSG_DEBUG, "EAP: building EAP-Request: Identifier %d", sm->currentId);
	sm->lastId = sm->currentId;
	sm->eap_if.eapReqData = sm->m->buildReq(sm, sm->eap_method_priv, sm->currentId);    # phase1 调用buildReq() -> 指向注册函数 eap_peap_buildReq()
}


# src/eap_server/eap_server_peap.c
static struct wpabuf * eap_peap_buildReq(struct eap_sm *sm, void *priv, u8 id)      # 被注册 eap->buildReq = eap_peap_buildReq;
{
	if (data->ssl.state == FRAG_ACK) {
		return eap_server_tls_build_ack(id, EAP_TYPE_PEAP, data->peap_version);		# 处理客户端发过来分包. 实际用不上!!!
	}

	if (data->ssl.state == WAIT_FRAG_ACK) {		# 服务端需给客户端分包
		return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_PEAP, data->peap_version, id);		# 包装好报文
	}

	switch (data->state) {
		case START:		# 枚举值: 0
			return eap_peap_build_start(sm, data, id);		# 1报文: eap_peap_start. 这里参数有 peap_version 区别
		case PHASE1:	# 枚举值: 1
		case PHASE1_ID2:									# 2和3报文: server_hello和change_cipher_spec
			if (tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
				wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase1 done, starting Phase2");
				eap_peap_state(data, PHASE2_START);
			}
			break;
		case PHASE2_ID:			# 枚举值: 4
		case PHASE2_METHOD:		# 枚举值: 5
			data->ssl.tls_out = eap_peap_build_phase2_req(sm, data, id);	# 4和5报文: peap_identity, peap_password. 调用下方. phase1(PEAP) 调用 phase2(GTC, MSCHAPV2)
			break;
		case PHASE2_TLV:
			data->ssl.tls_out = eap_peap_build_phase2_tlv(sm, data, id);
			break;
		case SUCCESS_REQ:		# 枚举值: 8
			data->ssl.tls_out = eap_peap_build_phase2_term(sm, data, id, 1);	# 6报文: eap_peap_success.
			break;
		case FAILURE_REQ:
			data->ssl.tls_out = eap_peap_build_phase2_term(sm, data, id, 0);
			break;
	}

	return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_PEAP, data->peap_version, id);		# 包装好报文
}


# src/eap_server/eap_server_peap.c
static struct wpabuf * eap_peap_build_phase2_req(struct eap_sm *sm, struct eap_peap_data *data, u8 id)
{
	buf = data->phase2_method->buildReq(sm, data->phase2_priv, id);     # phase2 调用buildReq(), 获取应答报文. -> 指向注册函数 eap_gtc_buildReq() 或 eap_mschapv2_buildReq()

	wpa_hexdump_key(MSG_DEBUG, "EAP-PEAP: Encrypting Phase 2 data", req, req_len);	# 打印

	if (data->peap_version == 0 && data->phase2_method->method != EAP_TYPE_TLV) {
		req += sizeof(struct eap_hdr);			# 如果是 PEAPv0, 则减去包头
		req_len -= sizeof(struct eap_hdr);
	}

	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);     # 加密
}


static struct wpabuf * eap_gtc_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	msg = data->prefix ? "CHALLENGE=Password" : "Password";

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_GTC, msg_len, EAP_CODE_REQUEST, id);	# 构造EAP消息Header
}
