#ifndef LIB_WSCLIENT_H_
#define LIB_WSCLIENT_H_

#include <stddef.h>
#include <pthread.h>
#ifdef HAVE_MBEDTLS
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

#ifndef FRAME_CHUNK_LENGTH
  #define FRAME_CHUNK_LENGTH 1024
#endif
#ifndef HELPER_RECV_BUF_SIZE
  #define HELPER_RECV_BUF_SIZE 1024
#endif

#define FLAG_CLIENT_IS_SSL (1 << 0)
#define FLAG_CLIENT_CONNECTING (1 << 1)
#define FLAG_CLIENT_CLOSEING (1 << 2)  //The last frame (close) is sent, and no more data is allowed to be sent afterwards.
#define FLAG_CLIENT_QUIT (1 << 3)
#define FLAG_CLIENT_IS_THREAD (1 << 4)

#define FLAG_REQUEST_HAS_CONNECTION (1 << 0)
#define FLAG_REQUEST_HAS_UPGRADE (1 << 1)
#define FLAG_REQUEST_VALID_STATUS (1 << 2)
#define FLAG_REQUEST_VALID_ACCEPT (1 << 3)

struct stream_buff {
  char data[HELPER_RECV_BUF_SIZE];
  ssize_t len;
  ssize_t pos;
};

enum _WS_OP_CODE_
{
  OP_CODE_CONTINUE = 0,
  OP_CODE_TYPE_TEXT = 1,
  OP_CODE_TYPE_BINARY = 2,
  OP_CODE_CONTROL_CLOSE = 8,
  OP_CODE_CONTROL_PING = 9,
  OP_CODE_CONTROL_PONG = 10,
};

typedef struct _wsclient_frame_in
{
  unsigned int fin;
  unsigned int opcode;
  unsigned long long payload_len;
  unsigned char *payload;
  struct _wsclient_frame_in *next_frame;
  struct _wsclient_frame_in *prev_frame;
} wsclient_frame_in;


typedef struct _wsclient
{
  pthread_t handshake_thread;
  pthread_t run_thread;
  pthread_t periodic_thread;
  pthread_mutex_t lock;
  pthread_mutex_t send_lock;
  int interval;
  char *URI;
  char *origin;
  int sockfd;
  int flags;
  void (*onopen)(struct _wsclient *);
  void (*onclose)(struct _wsclient *);
  void (*onerror)(struct _wsclient *, int code, const char *msg);
  void (*onmessage)(
    struct _wsclient *, int opcode, size_t lenth, const unsigned char *data
  );
  void (*onperiodic)(struct _wsclient *);
  wsclient_frame_in *current_frame;
  #ifdef HAVE_MBEDTLS
  mbedtls_net_context net;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  #endif
  void *userdata;
  struct stream_buff buf;
} wsclient;

// Function defs

wsclient *libwsclient_new(const char *URI, int as_thread);
wsclient *libwsclient_new_with_origin(const char *URI, const char *origin, int as_thread);

void libwsclient_start_run(wsclient *c);

void libwsclient_wait_for_end(wsclient *client);

void libwsclient_close(wsclient *c, char *reason);
void libwsclient_stop(wsclient *c);

void libwsclient_send_data(
  wsclient *client, int opcode, const unsigned char *payload,
  size_t payload_len
);
void libwsclient_send_string(wsclient *client, const char *payload);

void libwsclient_send_ping(wsclient *client, const char *payload);

#endif /* LIB_WSCLIENT_H_ */
