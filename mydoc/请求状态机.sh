############ 处理请求, 解密

# eap_server.c
SM_STATE(EAP, METHOD_RESPONSE)		sm_EAP_METHOD_RESPONSE_Enter()
	sm->m->process(sm, sm->eap_method_priv, sm->eap_if.eapRespData);	# 调用注册函数 eap->process = eap_peap_process;


# src/eap_server/eap_server_peap.c
static void eap_peap_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
	if (eap_server_tls_process(sm, &data->ssl, respData, data, EAP_TYPE_PEAP, eap_peap_process_version, eap_peap_process_msg) < 0) {


# src/eap_server/eap_server_peap.c
static void eap_peap_process_msg(struct eap_sm *sm, void *priv, const struct wpabuf *respData)		# 服务端处理从客户端发过来的消息
{
	struct eap_peap_data *data = priv;

	switch (data->state) {
	case PHASE1:
		if (eap_server_tls_phase1(sm, &data->ssl) < 0) {
			eap_peap_state(data, FAILURE);
			break;
		}
		break;
	case PHASE2_START:
		eap_peap_state(data, PHASE2_ID);
		eap_peap_phase2_init(sm, data, EAP_VENDOR_IETF,
				     EAP_TYPE_IDENTITY);
		break;
	case PHASE1_ID2:
	case PHASE2_ID:
	case PHASE2_METHOD:
	case PHASE2_SOH:
	case PHASE2_TLV:
		eap_peap_process_phase2(sm, data, respData, data->ssl.tls_in);
		break;
	case SUCCESS_REQ:
		eap_peap_state(data, SUCCESS);
		eap_peap_valid_session(sm, data);
		break;
	case FAILURE_REQ:
		eap_peap_state(data, FAILURE);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Unexpected state %d in %s",
			   data->state, __func__);
		break;
	}
}


# src/eap_server/eap_server_peap.c
static void eap_peap_process_phase2(struct eap_sm *sm,
				    struct eap_peap_data *data,
				    const struct wpabuf *respData,
				    struct wpabuf *in_buf)


# src/crypto/tls_openssl.c
struct wpabuf * tls_connection_decrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
