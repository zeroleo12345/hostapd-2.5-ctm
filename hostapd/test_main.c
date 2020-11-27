#include "includes.h"
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif /* __linux__ */

#include "common.h"
#include "../src/crypto/tls.h"
extern int wpa_debug_level;
void set_log_level( int log_level ){
    wpa_debug_level = log_level; //MSG_EXCESSIVE = 0 , MSG_MSGDUMP =1 , MSG_DEBUG = 2, MSG_INFO = 3, MSG_WARNING = 4, MSG_ERROR = 5
}

void py_os_free( void *ptr ){
    if( ptr ) os_free(ptr);
    ptr = NULL;
}

struct wpabuf * py_wpabuf_alloc(u8 * data, size_t data_len){
    struct wpabuf * st_wpabuf = wpabuf_alloc(data_len+1);
    st_wpabuf->used = data_len;
    st_wpabuf->buf = data;
    return st_wpabuf;
}

void myprint(const u8 *in_data, size_t in_len, int isIn) {
    if( wpa_debug_level > MSG_DEBUG )
        return;
    if( isIn )
        printf("INPUT len:%ld\n", in_len);
    else
        printf("OUTPUT len:%ld\n", in_len);

    int i;
    for( i=0; i < in_len; i++){
        printf("%02X", in_data[i]);
    }
    printf("\n");
}

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* OPENSSL_NO_ENGINE */
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif

struct tls_connection {
    struct tls_context *context;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *ssl_in, *ssl_out;
#ifndef OPENSSL_NO_ENGINE
    ENGINE *engine;        /* functional reference to the engine */
    EVP_PKEY *private_key; /* the private key if using engine */
#endif /* OPENSSL_NO_ENGINE */
    char *subject_match, *altsubject_match, *suffix_match, *domain_match;
    int read_alerts, write_alerts, failed;

    tls_session_ticket_cb session_ticket_cb;
    void *session_ticket_cb_ctx;

    /* SessionTicket received from OpenSSL hello_extension_cb (server) */
    u8 *session_ticket;
    size_t session_ticket_len;

    unsigned int ca_cert_verify:1;
    unsigned int cert_probe:1;
    unsigned int server_cert_only:1;
    unsigned int invalid_hb_used:1;
    unsigned int success_data:1;

    u8 srv_cert_hash[32];

    unsigned int flags;

    X509 *peer_cert;
    X509 *peer_issuer;
    X509 *peer_issuer_issuer;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    unsigned char client_random[SSL3_RANDOM_SIZE];
    unsigned char server_random[SSL3_RANDOM_SIZE];
#endif
};

void* py_authsrv_init(char *ca_cert_path, char *client_cert_path,
        char *private_key_path, char *private_key_passwd, char *dh_file_path) {
    wpa_printf(MSG_INFO, "ca_cert_path: (%s)", ca_cert_path);
    wpa_printf(MSG_INFO, "client_cert_path: (%s)", client_cert_path);
    wpa_printf(MSG_INFO, "private_key_path: (%s)", private_key_path);
    wpa_printf(MSG_INFO, "private_key_passwd: (%s)", private_key_passwd);
    wpa_printf(MSG_INFO, "dh_file_path: (%s)", dh_file_path);
    if(access(ca_cert_path, R_OK) != 0) {
        wpa_printf(MSG_ERROR, "ca_cert_path(%s) not exist.", ca_cert_path);
        return NULL;
    }
    if(access(client_cert_path, R_OK) != 0) {
        wpa_printf(MSG_ERROR, "client_cert_path(%s) not exist.", client_cert_path);
        return NULL;
    }
    if(access(private_key_path, R_OK) != 0) {
        wpa_printf(MSG_ERROR, "private_key_path(%s) not exist.", private_key_path);
        return NULL;
    }
    if(access(dh_file_path, R_OK) != 0) {
        wpa_printf(MSG_ERROR, "dh_file_path(%s) not exist.", dh_file_path);
        return NULL;
    }

    struct tls_config conf;
    os_memset(&conf, 0, sizeof(conf));

    void *ssl_ctx = tls_init(&conf); //return os_zalloc(X)
    if (ssl_ctx == NULL) {
        wpa_printf(MSG_ERROR, "Failed to initialize TLS");
        return NULL;
    }

    //struct tls_global *global = ssl_ctx;
    struct tls_connection_params params;
    os_memset(&params, 0, sizeof(params));
    params.ca_cert = ca_cert_path;              // "/etc/pki/CA/cacert.pem"
    params.client_cert = client_cert_path;      // "/etc/pki/CA/certs/servercert.pem"
    params.private_key = private_key_path;      // "/etc/pki/CA/private/serverkey.pem"
    params.private_key_passwd = private_key_passwd;     // "965pcsCTMRadius"
    params.dh_file = dh_file_path;                   // "/etc/pki/CA/dh"
    params.openssl_ciphers = NULL;
    params.ocsp_stapling_response = NULL;

    // global cert.  os_zalloc(struct tlsv1_credentials *server_cred;) py_os_free()
    if (tls_global_set_params(ssl_ctx, &params)) {
        wpa_printf(MSG_ERROR, "Failed to set TLS parameters");
        tls_deinit(ssl_ctx);
        return NULL;
    }
    wpa_printf(MSG_INFO, "py_authsrv_init success.");
    return ssl_ctx;
}

struct wpabuf * py_tls_connection_decrypt(void *ssl_ctx, void *conn, struct wpabuf *in_buf) {
    struct wpabuf *in_decrypted = tls_connection_decrypt(ssl_ctx, conn, in_buf);
    if (in_decrypted == NULL) {
        printf("EAP-PEAP: Failed to decrypt Phase 2 data.\n");
        return NULL;
    }
    return in_decrypted;
    //wpabuf_free(in_decrypted);
}

struct wpabuf * py_tls_connection_encrypt(void *ssl_ctx, void *conn, const struct wpabuf *plain) {
    struct wpabuf *buf = tls_connection_encrypt(ssl_ctx, conn, plain);
    if (buf == NULL) {
        printf("SSL: Failed to encrypt Phase 2 data.\n");
        return NULL;
    }
    return buf;
    //wpabuf_free(in_decrypted);
}

/*
 * const char * label = "client EAP encryption";
 * size_t len = 64;
 */
u8 * py_tls_connection_prf(void *ssl_ctx, struct tls_connection *conn, char *label, size_t len) {
    u8 *out = os_malloc(len);
    if (out == NULL)
        return NULL;

    if (tls_connection_prf(ssl_ctx, conn, label, 0, 0, out, len)) {
        py_os_free(out);
        return NULL;
    }
    return out;
    //py_os_free(out);
}

int main(int argc, char *argv[])
{
    set_log_level(MSG_MSGDUMP);
    // start
    char *ca_cert_path = "/Users/zlx/github/radius_server/etc/simulator/certs/ca.cer.pem";
    char *client_cert_path = "/Users/zlx/github/radius_server/etc/simulator/certs/server.cer.pem";
    char *private_key_path = "/Users/zlx/github/radius_server/etc/simulator/certs/server.key.pem";
    char *private_key_passwd = "1234";
    char *dh_file_path = "/Users/zlx/github/radius_server/etc/simulator/certs/dh";
    void *ssl_ctx = py_authsrv_init(ca_cert_path, client_cert_path, private_key_path, private_key_passwd, dh_file_path); //tls_deinit();
    if( ssl_ctx == NULL ){
        printf("[E] py_authsrv_init failed!\n");
        return -1;
    }

    // 定义:  src/crypto/tls_none.c:31:struct tls_connection * tls_connection_init(void *tls_ctx)
    struct tls_connection *conn = tls_connection_init(ssl_ctx); // tls_connection_deinit(ssl_ctx, conn);
    if (conn == NULL) {
        printf("[E] SSL: Failed to initialize new TLS connection!\n");
        tls_deinit(ssl_ctx);
        return -1;
    } else {
        printf("tls_connection_init success.\n");
    }

    // read input
    unsigned char buffer[1024];
    int fd = open("./c_client_hello1", O_RDONLY);
    if( fd == -1 ){
        printf("open file failed.\n");
        tls_deinit(ssl_ctx);
        return -1;
    }
    int size = read(fd, buffer, sizeof(buffer));
    close(fd);
    /*
    int i;
    for( i=0; i < size; i++){
        printf("%02X", buffer[i]);
    }
    printf("\nlen of input:%d\n", size);
    */
    // 1. each packet new one server handler
    //struct tlsv1_server *server = NULL;
    // os_zalloc(struct tlsv1_server *conn;) py_os_free()
    /*
    void *server = py_tlsv1_server_init((void*)global);
    if (server == NULL) {
        printf("py_tlsv1_server_init failed.\n");
        py_os_free(global);
        return -1; 
    }*/   

    // 2. call handler function
    u8 * in_data = buffer;
    size_t in_data_len = size;
    /*
    u8 *response = NULL;
    size_t response_len = 0;
    response = py_tlsv1_server_handshake(server, in_data, in_data_len, &response_len);
    if( response == NULL ) {
        printf("py_tlsv1_server_handshake failed.\n");
        py_os_free(response);
        py_os_free(server);
        py_os_free(server_cred);
        py_os_free(global);
        return -1;
    }*/
    //struct wpabuf * tls_in = wpabuf_alloc(in_data_len+1);
    //tls_in->used = in_data_len;
    //tls_in->buf = in_data;
    struct wpabuf * tls_in = py_wpabuf_alloc(in_data, in_data_len);

    myprint(tls_in->buf, tls_in->used, 1);
    struct wpabuf *tls_out = tls_connection_server_handshake(ssl_ctx, conn, tls_in, NULL);
    if (tls_out == NULL) {
        printf("[E] SSL: TLS processing failed!\n");
        tls_connection_deinit(ssl_ctx, conn);
        tls_deinit(ssl_ctx);
        return -1;
    } else {
        printf("tls_connection_server_handshake success.\n");
    }

    myprint(tls_out->buf, tls_out->used, 0);
    wpabuf_free(tls_in);
    wpabuf_free(tls_out);
    tls_connection_deinit(ssl_ctx, conn);
    tls_deinit(ssl_ctx);
    printf("main end normal.\n");
    return 0;
}
