# src/eap_server/eap_server_peap.c
# 状态机 PHASE2_ID, PHASE2_METHOD:
static struct wpabuf * eap_peap_build_phase2_req(struct eap_sm *sm, struct eap_peap_data *data, u8 id)
	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);

# 状态机 PHASE2_SOH: 需定义 EAP_SERVER_TNC. 用不上!!!
static struct wpabuf * eap_peap_build_phase2_soh(struct eap_sm *sm, struct eap_peap_data *data, u8 id)
	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);

# 状态机 PHASE2_TLV:
static struct wpabuf * eap_peap_build_phase2_tlv(struct eap_sm *sm, struct eap_peap_data *data, u8 id)
	encr_req = eap_server_tls_encrypt(sm, &data->ssl, buf);

# 状态机 SUCCESS_REQ, FAILURE_REQ: 发送 EAP_CODE_SUCCESS
static struct wpabuf * eap_peap_build_phase2_term(struct eap_sm *sm, struct eap_peap_data *data, u8 id, int success)
	encr_req = eap_server_tls_encrypt(sm, &data->ssl, &msgbuf);


# src/eap_server/eap_server_tls_common.c	其中common表示是所有认证方式公用的
struct wpabuf * eap_server_tls_encrypt(struct eap_sm *sm, struct eap_ssl_data *data, const struct wpabuf *plain)
{
	struct wpabuf *buf;

	buf = tls_connection_encrypt(sm->ssl_ctx, data->conn,
				     plain);
	if (buf == NULL) {
		wpa_printf(MSG_INFO, "SSL: Failed to encrypt Phase 2 data");
		return NULL;
	}

	return buf;
}


# src/crypto/tls_openssl.c
struct wpabuf * tls_connection_encrypt(void *tls_ctx, struct tls_connection *conn, const struct wpabuf *in_data)

