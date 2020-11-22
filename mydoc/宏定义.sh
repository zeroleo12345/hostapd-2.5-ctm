# src/utils/state_machine.h
define SM_STEP(machine)				定义方法
	static void sm_ ## machine ## _Step(STATE_MACHINE_DATA *sm)

define SM_STEP_RUN(machine)		调用方法
	sm_ ## machine ## _Step(sm)


define SM_STATE(machine, state)		定义方法
	static void sm_ ## machine ## _ ## state ## _Enter(STATE_MACHINE_DATA *sm, int global)


define SM_ENTER(machine, state)		调用方法
	sm_ ## machine ## _ ## state ## _Enter(sm, 0)


define SM_ENTRY(machine, state)		设置状态机当前状态
	sm->machine ## _state = machine ## _ ## state;


#
define MSCHAPV2_OP_CHALLENGE 1
define MSCHAPV2_OP_RESPONSE 2
define MSCHAPV2_OP_SUCCESS 3
define MSCHAPV2_OP_FAILURE 4


####################
typedef enum {
	EAP_TYPE_NONE = 0,
	EAP_TYPE_IDENTITY = 1 /* RFC 3748 */,
	EAP_TYPE_NOTIFICATION = 2 /* RFC 3748 */,
	EAP_TYPE_NAK = 3 /* Response only, RFC 3748 */,
	EAP_TYPE_MD5 = 4, /* RFC 3748 */
	EAP_TYPE_OTP = 5 /* RFC 3748 */,
	EAP_TYPE_GTC = 6, /* RFC 3748 */
	EAP_TYPE_TLS = 13 /* RFC 2716 */,
	EAP_TYPE_LEAP = 17 /* Cisco proprietary */,
	EAP_TYPE_SIM = 18 /* RFC 4186 */,
	EAP_TYPE_TTLS = 21 /* RFC 5281 */,
	EAP_TYPE_AKA = 23 /* RFC 4187 */,
	EAP_TYPE_PEAP = 25 /* draft-josefsson-pppext-eap-tls-eap-06.txt */,
	EAP_TYPE_MSCHAPV2 = 26 /* draft-kamath-pppext-eap-mschapv2-00.txt */,
	EAP_TYPE_TLV = 33 /* draft-josefsson-pppext-eap-tls-eap-07.txt */,
	EAP_TYPE_TNC = 38 /* TNC IF-T v1.0-r3; note: tentative assignment;
			   * type 38 has previously been allocated for
			   * EAP-HTTP Digest, (funk.com) */,
	EAP_TYPE_FAST = 43 /* RFC 4851 */,
	EAP_TYPE_PAX = 46 /* RFC 4746 */,
	EAP_TYPE_PSK = 47 /* RFC 4764 */,
	EAP_TYPE_SAKE = 48 /* RFC 4763 */,
	EAP_TYPE_IKEV2 = 49 /* RFC 5106 */,
	EAP_TYPE_AKA_PRIME = 50 /* RFC 5448 */,
	EAP_TYPE_GPSK = 51 /* RFC 5433 */,
	EAP_TYPE_PWD = 52 /* RFC 5931 */,
	EAP_TYPE_EKE = 53 /* RFC 6124 */,
	EAP_TYPE_EXPANDED = 254 /* RFC 3748 */
} EapType;
