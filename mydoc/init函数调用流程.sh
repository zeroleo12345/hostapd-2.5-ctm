eap->init = eap_peap_init;      # 注册init函数

# src/eap_server/eap_server.c
SM_STATE(EAP, PICK_UP_METHOD)       # EAP_INITIALIZE -> PICK_UP_METHOD
    sm->m = eap_server_get_eap_method(EAP_VENDOR_IETF, sm->currentMethod);     # phase1 认证函数 init

SM_STATE(EAP, PROPOSE_METHOD)
    sm->eap_method_priv = sm->m->init(sm);      # 调用 phase1 认证函数 init


# src/eap_server/eap_server_peap.c
static void eap_peap_process_msg(struct eap_sm *sm, void *priv, const struct wpabuf *respData)
	case PHASE2_START:
		eap_peap_state(data, PHASE2_ID);
		eap_peap_phase2_init(sm, data, EAP_VENDOR_IETF, EAP_TYPE_IDENTITY);

# src/eap_server/eap_server_peap.c
static int eap_peap_phase2_init(struct eap_sm *sm, struct eap_peap_data *data, int vendor, EapType eap_type)
    data->phase2_priv = data->phase2_method->init(sm);      # 调用 phase2 认证函数 init


###############################
# src/eap_server/eap_server_peap.c
static void * eap_peap_init(struct eap_sm *sm)
{
	if (eap_server_tls_ssl_init(sm, &data->ssl, 0, EAP_TYPE_PEAP)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to initialize SSL.");
		eap_peap_reset(sm, data);
		return NULL;
	}

	return data;
}


int eap_server_tls_ssl_init(struct eap_sm *sm, struct eap_ssl_data *data, int verify_peer, int eap_type)
{
	data->conn = tls_connection_init(sm->ssl_ctx);
	if (data->conn == NULL) {
		wpa_printf(MSG_INFO, "SSL: Failed to initialize new TLS "
			   "connection");
		return -1;
	}

	if (tls_connection_set_verify(sm->ssl_ctx, data->conn, verify_peer,     # 分析过内部逻辑, 可以不调用?
				      flags, session_ctx,
				      sizeof(session_ctx))) {
		wpa_printf(MSG_INFO, "SSL: Failed to configure verification "
			   "of TLS peer certificate");
		tls_connection_deinit(sm->ssl_ctx, data->conn);
		data->conn = NULL;
		return -1;
	}

	return 0;
}
