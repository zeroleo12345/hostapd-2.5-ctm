#include <stdlib.h>
#include <stdio.h>

// dlopen
#include <dlfcn.h>
// error
//#include <errno.h>
// strerror
//#include <string.h>
// uint8_t
#include <stdint.h>
// O_RDONLY
#include <fcntl.h>
// read
#include <unistd.h>

/*
 * reference:  char *dlerror(void);
 *      当动态链接库操作函数执行失败时，dlerror可以返回出错信息，返回值为NULL时表示操作函数执行成功。
 *
 * function: 
 *      int py_tlsv1_server_handshake(int a) { print "test"; }
 * usage:
 *      int (*py_tlsv1_server_handshake)(int) = (int(*)(int))::dlsym(handler, "py_tlsv1_server_handshake");
 *
 * function: 
 *      void py_tlsv1_server_handshake() { print "test"; }
 * usage:
 *      void (*py_tlsv1_server_handshake)() = (void(*)())::dlsym(handler, "py_tlsv1_server_handshake");
 *
 *
*/

/*
typedef uint8_t u8;
struct tls_global {
    int server;
    struct tlsv1_credentials *server_cred;
    int check_crl;
};
*/

int main(int argc, char *argv[])
{
    char *error = NULL;
    char* libpath = (char*)"./libhostapd.so";
    printf("global:%d, lazy:%d, local:%d\n", RTLD_GLOBAL, RTLD_LAZY, RTLD_LOCAL);
    void* handler = dlopen(libpath, RTLD_GLOBAL|RTLD_LAZY); //RTLD_LAZY RTLD_LOCAL RTLD_GLOBAL
    if(handler == NULL) {
        printf("open library(%s) failed.dlerror:%s\n", libpath, dlerror());
        return -1;
    }

    /*
     void* py_tlsv1_server_init(void * _global)
     u8* py_tlsv1_server_handshake(void *_server, const u8 *in_data, size_t in_len, size_t *out_len)
     void* py_global_init(void *out_cred)
     */
    // 加载函数指针 start
    void* (*py_tlsv1_server_init)(void *) = (void* (*)(void *))::dlsym(handler, "py_tlsv1_server_init");
    if ( ( error = dlerror() ) != NULL) {
        printf ("dlerror:%s\n", error);
        return -1;
    }

    uint8_t* (*py_tlsv1_server_handshake)(void*, const uint8_t*, size_t, size_t*) = (uint8_t* (*)(void*, const uint8_t*, size_t, size_t*))::dlsym(handler, "py_tlsv1_server_handshake");
    if ( ( error = dlerror() ) != NULL) {
        printf ("dlerror:%s\n", error);
        return -1;
    }

    void* (*py_global_init)(void*) = (void* (*)(void*))::dlsym(handler, "py_global_init");
    if ( ( error = dlerror() ) != NULL) {
        printf ("dlerror:%s\n", error);
        return -1;
    }

    void (*py_free)(void*) = (void (*)(void*))::dlsym(handler, "py_free");
    if ( ( error = dlerror() ) != NULL) {
        printf ("dlerror:%s\n", error);
        return -1;
    }
    // 加载函数指针 end

    // start
    void *server_cred = NULL;
    void *global = py_global_init(server_cred);
    if( global == NULL ){
        printf("py_global_init failed.\n");
        return -1;
    }

    // read input
    int fd, size;
    unsigned char buffer[1024];
    fd = open("./c_client_hello1", O_RDONLY);
    size = read(fd, buffer, sizeof(buffer));
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
    // os_zalloc(struct tlsv1_server *conn;) os_free()
    void *server = py_tlsv1_server_init((void*)global);
    if (server == NULL) {
        printf("py_tlsv1_server_init failed.\n");
        py_free(global);
        return -1; 
    }
    // 2. call handler function
    uint8_t *response = NULL;
    size_t response_len = 0;
    uint8_t * in_data = buffer;
    size_t in_data_len = size;
    //u8* py_tlsv1_server_handshake(void *_server, const u8 *in_data, size_t in_len, size_t *out_len)
    response = py_tlsv1_server_handshake(server, in_data, in_data_len, &response_len);
    if( response == NULL ) {
        printf("py_tlsv1_server_handshake failed.\n");
        py_free(response);
        py_free(server);
        py_free(server_cred);
        py_free(global);
        return -1;
    }
    printf("sizeof(size_t):%d\n", sizeof(size_t));
    py_free(response);
    py_free(server);
    py_free(server_cred);
    py_free(global);
    dlclose(handler);
    printf("finish.\n");
    return 0;
}
