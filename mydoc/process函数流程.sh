process() 主要是 调动 eap_peap_phase2_init() 初始化, 以及设置 state 变更 


# src/eap_server/eap_server.c
SM_STATE(EAP, METHOD_RESPONSE)      # 在主流程中!!!
{
	SM_ENTRY(EAP, METHOD_RESPONSE);

	sm->m->process(sm, sm->eap_method_priv, sm->eap_if.eapRespData);    # phase1 调用 process() -> 指向注册函数 eap_peap_process()
}



# src/eap_server/eap_server_peap.c
static void eap_peap_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)    # 被注册 eap->process = eap_peap_process;
	if (eap_server_tls_process(sm, &data->ssl, respData, data, EAP_TYPE_PEAP, eap_peap_process_version, eap_peap_process_msg) < 0) {    # 通过传入的回调函数调用下面
		eap_peap_state(data, FAILURE);
		return;
	}


# src/eap_server/eap_server_peap.c
static void eap_peap_process_msg(struct eap_sm *sm, void *priv,
				 const struct wpabuf *respData)
{
    wpa_printf(MSG_INFO, "123456 eap_peap_process_msg() data->state=%d", data->state);
	switch (data->state) {
	case PHASE1:
		if (eap_server_tls_phase1(sm, &data->ssl) < 0) {
			eap_peap_state(data, FAILURE);
			break;
		}
		break;
	case PHASE2_START:
		eap_peap_state(data, PHASE2_ID);
		eap_peap_phase2_init(sm, data, EAP_VENDOR_IETF, EAP_TYPE_IDENTITY);
		break;
	case PHASE1_ID2:
	case PHASE2_ID:
	case PHASE2_METHOD:
	case PHASE2_SOH:
	case PHASE2_TLV:
		eap_peap_process_phase2(sm, data, respData, data->ssl.tls_in);      # 调用下面膜
		break;
	case SUCCESS_REQ:
		eap_peap_state(data, SUCCESS);
		eap_peap_valid_session(sm, data);
		break;
	case FAILURE_REQ:
		eap_peap_state(data, FAILURE);
		break;
	}
}



# src/eap_server/eap_server_peap.c
static void eap_peap_process_phase2(struct eap_sm *sm, struct eap_peap_data *data, const struct wpabuf *respData, struct wpabuf *in_buf)
	case EAP_CODE_RESPONSE:
		eap_peap_process_phase2_response(sm, data, in_decrypted);   # 调用下面
		break;


# src/eap_server/eap_server_peap.c
static void eap_peap_process_phase2_response(struct eap_sm *sm, struct eap_peap_data *data, struct wpabuf *in_data)
{
	if (data->state == PHASE2_TLV) {
		eap_peap_process_phase2_tlv(sm, data, in_data);
		return;
	}

	data->phase2_method->process(sm, data->phase2_priv, in_data);       # phase2 调用 process() -> 指向注册函数 eap_gtc_process 或者 eap_mschapv2_process

	if (!data->phase2_method->isDone(sm, data->phase2_priv))
		return;

	if (!data->phase2_method->isSuccess(sm, data->phase2_priv)) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 method failed");
		eap_peap_req_failure(sm, data);
		next_vendor = EAP_VENDOR_IETF;
		next_type = EAP_TYPE_NONE;
		eap_peap_phase2_init(sm, data, next_vendor, next_type);
		return;
	}

	os_free(data->phase2_key);
	if (data->phase2_method->getKey) {
		data->phase2_key = data->phase2_method->getKey(sm, data->phase2_priv, &data->phase2_key_len);
		if (data->phase2_key == NULL) {
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 getKey failed");
			eap_peap_req_failure(sm, data);
			eap_peap_phase2_init(sm, data, EAP_VENDOR_IETF, EAP_TYPE_NONE);
			return;
		}
	}

	switch (data->state) {
	case PHASE1_ID2:
	case PHASE2_ID:
	case PHASE2_SOH:
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP_PEAP: Phase2 Identity not found in the user database", sm->identity, sm->identity_len);
			eap_peap_req_failure(sm, data);
			next_vendor = EAP_VENDOR_IETF;
			next_type = EAP_TYPE_NONE;
			break;
		}

		eap_peap_state(data, PHASE2_METHOD);
		next_vendor = sm->user->methods[0].vendor;
		next_type = sm->user->methods[0].method;
		sm->user_eap_method_index = 1;
		wpa_printf(MSG_DEBUG, "EAP-PEAP: try EAP vendor %d type 0x%x", next_vendor, next_type);
		break;
	case PHASE2_METHOD:
		eap_peap_req_success(sm, data);
		next_vendor = EAP_VENDOR_IETF;
		next_type = EAP_TYPE_NONE;
		break;
	case FAILURE:
		break;

	eap_peap_phase2_init(sm, data, next_vendor, next_type);
}
