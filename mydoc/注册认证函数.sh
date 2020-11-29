# hostapd/eap_register.c
int eap_server_register_methods(void)
{
#ifdef EAP_SERVER_MSCHAPV2  不用理会
	if (ret == 0)
		ret = eap_server_mschapv2_register();
#endif /* EAP_SERVER_MSCHAPV2 */

#ifdef EAP_SERVER_PEAP
	if (ret == 0)
		ret = eap_server_peap_register();
#endif /* EAP_SERVER_PEAP */

#ifdef EAP_SERVER_GTC   不用理会
	if (ret == 0)
		ret = eap_server_gtc_register();
#endif /* EAP_SERVER_GTC */
}


# src/eap_server/eap_server_peap.c
int eap_server_peap_register(void)
{
	struct eap_method *eap;
	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_PEAP, "PEAP");		只有 "PEAP", "GTC", "MSCHAPV2", 而没有 "EAP". 处理顺序, 先用 phase1 处理函数 "PEAP" , 再用 phase2 处理函数 "GTC" 或 "MSCHAPV2"

	eap->init = eap_peap_init;
	eap->reset = eap_peap_reset;
	eap->buildReq = eap_peap_buildReq;
	eap->check = eap_peap_check;
	eap->process = eap_peap_process;
	eap->isDone = eap_peap_isDone;
	eap->getKey = eap_peap_getKey;
	eap->isSuccess = eap_peap_isSuccess;
	eap->getSessionId = eap_peap_get_session_id;

	ret = eap_server_method_register(eap);		# 调用下方注册
}


# 全局变量, 链表保存所有认证方法
static struct eap_method *eap_methods;

# src/eap_server/eap_server_methods.c
int eap_server_method_register(struct eap_method *method)        # 注册认证方法到全局变量 eap_methods
{
	struct eap_method *m, *last = NULL;

	if (method == NULL || method->name == NULL ||
	    method->version != EAP_SERVER_METHOD_INTERFACE_VERSION)
		return -1;

	for (m = eap_methods; m; m = m->next) {
		if ((m->vendor == method->vendor &&
		     m->method == method->method) ||
		    os_strcmp(m->name, method->name) == 0)
			return -2;
		last = m;
	}

	if (last)
		last->next = method;
	else
		eap_methods = method;

	return 0;
}


# src/eap_server/eap_server_methods.c
const struct eap_method * eap_server_get_eap_method(int vendor, EapType method)     # 从全局变量 eap_methods 返回对应认证方法
{
	struct eap_method *m;
	for (m = eap_methods; m; m = m->next) {
		if (m->vendor == vendor && m->method == method)
			return m;
	}
	return NULL;
}



###########
int eap_server_gtc_register(void)
{
	struct eap_method *eap;
	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_GTC, "GTC");

	eap->init = eap_gtc_init;
	eap->reset = eap_gtc_reset;
	eap->buildReq = eap_gtc_buildReq;
	eap->check = eap_gtc_check;
	eap->process = eap_gtc_process;
	eap->isDone = eap_gtc_isDone;
	eap->isSuccess = eap_gtc_isSuccess;

	ret = eap_server_method_register(eap);
}


int eap_server_mschapv2_register(void)
{
	struct eap_method *eap;
	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_MSCHAPV2,
				      "MSCHAPV2");

	eap->init = eap_mschapv2_init;
	eap->reset = eap_mschapv2_reset;
	eap->buildReq = eap_mschapv2_buildReq;
	eap->check = eap_mschapv2_check;
	eap->process = eap_mschapv2_process;
	eap->isDone = eap_mschapv2_isDone;
	eap->getKey = eap_mschapv2_getKey;
	eap->isSuccess = eap_mschapv2_isSuccess;

	ret = eap_server_method_register(eap);
}


## 协商认证协议
SM_STATE(EAP, PROPOSE_METHOD)
	type = eap_sm_Policy_getNextMethod(sm, &vendor);
	sm->m = eap_server_get_eap_method(vendor, type);