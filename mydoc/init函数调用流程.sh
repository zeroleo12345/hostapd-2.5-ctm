
# src/eap_server/eap_server.c
SM_STATE(EAP, PROPOSE_METHOD)		# 在主流程中!!!
	SM_ENTRY(EAP, PROPOSE_METHOD);		# 打印 EAP: EAP entering state PROPOSE_METHOD
    sm->eap_method_priv = sm->m->init(sm);      # phase1 调用 init() -> 指向注册函数 eap_peap_init()


# src/eap_server/eap_server_peap.c
static void eap_peap_process_msg(struct eap_sm *sm, void *priv, const struct wpabuf *respData)
	case PHASE2_START:
		eap_peap_state(data, PHASE2_ID);
		eap_peap_phase2_init(sm, data, EAP_VENDOR_IETF, EAP_TYPE_IDENTITY);

# src/eap_server/eap_server_peap.c
static int eap_peap_phase2_init(struct eap_sm *sm, struct eap_peap_data *data, int vendor, EapType eap_type)
    data->phase2_priv = data->phase2_method->init(sm);      # phase2 调用 init() -> 指向注册函数 eap_gtc_init() 或 eap_mschapv2_init()


###############################
# src/eap_server/eap_server_peap.c
static void * eap_peap_init(struct eap_sm *sm)		# 被注册 eap->init = eap_peap_init;
{
	if (eap_server_tls_ssl_init(sm, &data->ssl, 0, EAP_TYPE_PEAP)) {		# 调用下方, 初始化 ssl->conn
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to initialize SSL.");
		eap_peap_reset(sm, data);
		return NULL;
	}
}

# src/eap_erver/eap_server_tls_common.c
int eap_server_tls_ssl_init(struct eap_sm *sm, struct eap_ssl_data *data, int verify_peer, int eap_type)
{
	data->conn = tls_connection_init(sm->ssl_ctx);
	if (data->conn == NULL) {
		wpa_printf(MSG_INFO, "SSL: Failed to initialize new TLS connection");
		return -1;
	}

	if (tls_connection_set_verify(sm->ssl_ctx, data->conn, verify_peer,     # 分析过内部逻辑, 可以不调用?
				      flags, session_ctx,
				      sizeof(session_ctx))) {
		wpa_printf(MSG_INFO, "SSL: Failed to configure verification of TLS peer certificate");
		tls_connection_deinit(sm->ssl_ctx, data->conn);
		data->conn = NULL;
		return -1;
	}
}
