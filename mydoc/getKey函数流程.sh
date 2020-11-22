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
    data->phase2_key = data->phase2_method->getKey(sm, data->phase2_priv, &data->phase2_key_len);
}


# src/eap_server/eap_server_peap.c
static u8 * eap_peap_getKey(struct eap_sm *sm, void *priv, size_t *len)
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
