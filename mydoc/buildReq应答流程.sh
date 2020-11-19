EAP: getDecision: another method available -> CONTINUE
EAP-PEAP: START -> PHASE1
EAP-PEAP: PHASE1 -> PHASE2_START
EAP-PEAP: PHASE2_START -> PHASE2_ID
EAP-PEAP: PHASE2_ID -> PHASE2_METHOD
EAP-PEAP: PHASE2_METHOD -> SUCCESS_REQ
EAP-PEAP: SUCCESS_REQ -> SUCCESS


# src/eap_server/eap_server.c
SM_STATE(EAP, METHOD_REQUEST)
{
	SM_ENTRY(EAP, METHOD_REQUEST);

	if (sm->m == NULL) {
		wpa_printf(MSG_DEBUG, "EAP: method not initialized");
		return;
	}

	sm->currentId = eap_sm_nextId(sm, sm->currentId);
	wpa_printf(MSG_DEBUG, "EAP: building EAP-Request: Identifier %d", sm->currentId);
	sm->lastId = sm->currentId;
	sm->eap_if.eapReqData = sm->m->buildReq(sm, sm->eap_method_priv, sm->currentId);    # phase1 应答, 调用下方 eap_peap_buildReq
}


# src/eap_server/eap_server_peap.c
static struct wpabuf * eap_peap_buildReq(struct eap_sm *sm, void *priv, u8 id)      # 被注册的 buildReq 方法
{
	if (data->ssl.state == FRAG_ACK) {
		return eap_server_tls_build_ack(id, EAP_TYPE_PEAP, data->peap_version);		# 处理客户端发过来分包. 实际用不上!!!
	}

	if (data->ssl.state == WAIT_FRAG_ACK) {		# 服务端需给客户端分包
		return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_PEAP, data->peap_version, id);		# 包装好报文
	}

	switch (data->state) {
		case START:
			return eap_peap_build_start(sm, data, id);
		case PHASE1:
		case PHASE1_ID2:
			if (tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
				wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase1 done, "
					"starting Phase2");
				eap_peap_state(data, PHASE2_START);
			}
			break;
		case PHASE2_ID:
		case PHASE2_METHOD:
			data->ssl.tls_out = eap_peap_build_phase2_req(sm, data, id);	# peap外层流程调用phase2
			break;
		case PHASE2_TLV:
			data->ssl.tls_out = eap_peap_build_phase2_tlv(sm, data, id);
			break;
		case SUCCESS_REQ:
			data->ssl.tls_out = eap_peap_build_phase2_term(sm, data, id, 1);
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
	buf = data->phase2_method->buildReq(sm, data->phase2_priv, id);     # 调用 phase2 处理函数, 获取应答报文. 例如调用 eap_gtc_buildReq() 或 eap_mschapv2_buildReq()

	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);     # 加密
}
