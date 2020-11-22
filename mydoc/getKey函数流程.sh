# 生成 MS-MPPE-Recv-Key 和 MS-MPPE-Send-Key


# src/eap_server/eap_server.c
SM_STATE(EAP, METHOD_RESPONSE)
{
	SM_ENTRY(EAP, METHOD_RESPONSE);

    sm->eap_if.eapKeyData = sm->m->getKey(sm, sm->eap_method_priv, &sm->eap_if.eapKeyDataLen);
}



# src/eap_server/eap_server_peap.c
static void eap_peap_process_phase2_response(struct eap_sm *sm, struct eap_peap_data *data, struct wpabuf *in_data)
{
    data->phase2_key = data->phase2_method->getKey(sm, data->phase2_priv, &data->phase2_key_len);   # 提供下面的函数使用
}


# src/eap_server/eap_server_peap.c
static void eap_peap_get_isk(struct eap_peap_data *data, u8 *isk, size_t isk_len)       # 用 phase2_key 的地方, 但调用者 eap_peap_derive_cmk() 根据日志分析, 并没有触发! 所以 phase2 的 getKey() 没用!
{
	size_t key_len;

	os_memset(isk, 0, isk_len);
	if (data->phase2_key == NULL)
		return;

	key_len = data->phase2_key_len;
	if (key_len > isk_len)
		key_len = isk_len;
	os_memcpy(isk, data->phase2_key, key_len);
}



# src/eap_server/eap_server_peap.c
static u8 * eap_peap_getKey(struct eap_sm *sm, void *priv, size_t *len)     # peap方法
{
	struct eap_peap_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	if (data->crypto_binding_used) {    # 不会进入这里!
		u8 csk[128];
		/*
		 * Note: It looks like Microsoft implementation requires null
		 * termination for this label while the one used for deriving
		 * IPMK|CMK did not use null termination.
		 */
		if (peap_prfplus(data->peap_version, data->ipmk, 40,
				 "Session Key Generating Function",
				 (u8 *) "\00", 1, csk, sizeof(csk)) < 0)
			return NULL;
		wpa_hexdump_key(MSG_DEBUG, "EAP-PEAP: CSK", csk, sizeof(csk));
		eapKeyData = os_malloc(EAP_TLS_KEY_LEN);
		if (eapKeyData) {
			os_memcpy(eapKeyData, csk, EAP_TLS_KEY_LEN);
			*len = EAP_TLS_KEY_LEN;
			wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Derived key",
				    eapKeyData, EAP_TLS_KEY_LEN);
		} else {
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Failed to derive "
				   "key");
		}

		return eapKeyData;
	}

	/* TODO: PEAPv1 - different label in some cases */
	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl,
					       "client EAP encryption",
					       EAP_TLS_KEY_LEN);
	if (eapKeyData) {
		*len = EAP_TLS_KEY_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Derived key",
			    eapKeyData, EAP_TLS_KEY_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Failed to derive key");
	}

	return eapKeyData;
}


# src/eap_server/eap_server_mschapv2.c
static u8 * eap_mschapv2_getKey(struct eap_sm *sm, void *priv, size_t *len)     # mschapv2方法
{
	struct eap_mschapv2_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS || !data->master_key_valid)
		return NULL;

	*len = 2 * MSCHAPV2_KEY_LEN;
	key = os_malloc(*len);
	if (key == NULL)
		return NULL;
	/* MSK = server MS-MPPE-Recv-Key | MS-MPPE-Send-Key */
	get_asymetric_start_key(data->master_key, key, MSCHAPV2_KEY_LEN, 0, 1);
	get_asymetric_start_key(data->master_key, key + MSCHAPV2_KEY_LEN,
				MSCHAPV2_KEY_LEN, 1, 1);
	wpa_hexdump_key(MSG_DEBUG, "EAP-MSCHAPV2: Derived key", key, *len);

	return key;
}
