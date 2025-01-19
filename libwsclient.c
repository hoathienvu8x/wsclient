#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>

#include <sys/types.h>
#include <string.h>

#include <sys/time.h>
#include <math.h>

#include "./include/libwsclient.h"
#include "wsclient.h"

#include "sha1.h"
#include "utils.h"

#define MAX_PAYLOAD_PAD (MAX_PAYLOAD_SIZE - 15)

wsclient *libwsclient_new(const char *URI, int as_thread)
{
  wsclient *client = NULL;

  client = (wsclient *)calloc(sizeof(wsclient), 1);
  if (!client)
  {
    // LIBWSCLIENT_ON_ERROR(client, "Unable to allocate memory in libwsclient_new.\n");
    return NULL;
  }
  if (
    (pthread_mutex_init(&client->lock, NULL) != 0) ||
    (pthread_mutex_init(&client->send_lock, NULL) != 0)
  )
  {
    LIBWSCLIENT_ON_ERROR(
      client, "Unable to init mutex or send lock in libwsclient_new.\n"
    );
    free(client);
    return NULL;
  }
  update_wsclient_status(client, FLAG_CLIENT_CONNECTING, 0);
  client->URI = (char *)calloc(strlen(URI) + 1, 1);
  if (!client->URI)
  {
    LIBWSCLIENT_ON_ERROR(
      client, "Unable to allocate memory in libwsclient_new.\n"
    );
    free(client);
    return NULL;
  }
  strncpy(client->URI, URI, strlen(URI));
  client->as_thread = as_thread;

  if (client->as_thread)
  {
    if (pthread_create(
      &client->handshake_thread, NULL, libwsclient_handshake_thread,
      (void *)client)
    )
    {
      LIBWSCLIENT_ON_ERROR(client, "Unable to create handshake thread.\n");
      free(client);
      return NULL;
    }
  }
  return client;
}

void libwsclient_start_run(wsclient *c)
{
  if (TEST_FLAG(c, FLAG_CLIENT_CONNECTING))
  {
    if (c->as_thread)
    {
      pthread_join(c->handshake_thread, NULL);
    }
    else
    {
      (void)libwsclient_handshake_thread(c);
    }

    update_wsclient_status(c, 0, FLAG_CLIENT_CONNECTING);

    free(c->URI);
    c->URI = NULL;
  }
  if (c->sockfd)
  {
    if (c->as_thread)
    {
      pthread_create(&c->run_thread, NULL, libwsclient_run_thread, (void *)c);
    }
    else
    {
      (void)libwsclient_run_thread(c);
    }
  }
  else
  {
    LIBWSCLIENT_ON_ERROR(c, "network failed.\n");
  }
}

void libwsclient_wait_for_end(wsclient *client)
{
  if (client->run_thread)
  {
    pthread_join(client->run_thread, NULL);
  }
}

void libwsclient_close(wsclient *client, char *reason)
{
  if (!TEST_FLAG(client, FLAG_CLIENT_CLOSEING))
  {
    libwsclient_send_data(
      client, OP_CODE_CONTROL_CLOSE, (unsigned char*)reason, reason ? strlen(reason) : 0
    );
    update_wsclient_status(client, FLAG_CLIENT_CLOSEING, 0);
  };

  update_wsclient_status(client, FLAG_CLIENT_QUIT, 0);
  libwsclient_wait_for_end(client);
  pthread_mutex_destroy(&client->lock);
  pthread_mutex_destroy(&client->send_lock);
  if (TEST_FLAG(client, FLAG_CLIENT_IS_SSL))
  {
    #ifdef HAVE_OPENSSL
    if (client->ssl)
    {
      SSL_shutdown(client->ssl);
      SSL_free(client->ssl);
    }
    if (client->ssl_ctx)
    {
      SSL_CTX_free(client->ssl_ctx);
    }
    #endif
  }
  free(client);
}

void libwsclient_stop(wsclient *c)
{
  update_wsclient_status(c, FLAG_CLIENT_QUIT, 0);
}

void libwsclient_send_string(wsclient *client, char *payload)
{
  #ifdef DEBUG
  char buff[1024] = {0};
  sprintf(buff, "websocket sending data message: %s", payload);
  //if (ctl_frame->payload_len > 0)
  {
    LIBWSCLIENT_ON_INFO(client, buff);
  }
  #endif

  libwsclient_send_data(client, OP_CODE_TYPE_TEXT, (unsigned char *)payload, payload ? strlen(payload) : 0);
}

// Sending data
// client: wsclient object
// opcode: type, OP_CODE_TEXT or OP_CODE_BINARY
// payload: Data to be sent (utf8 string or byte data)
// payload_len: Length of data to be sent.
void libwsclient_send_data(
  wsclient *client, int opcode, unsigned char *payload,
  unsigned long long payload_len
)
{
  int mask_int = 0;

  struct timeval tv;
  gettimeofday(&tv, NULL);
  srand(tv.tv_usec * tv.tv_sec);
  mask_int = rand();

  if (TEST_FLAG(client, (FLAG_CLIENT_CLOSEING | FLAG_CLIENT_QUIT)))
  {
    LIBWSCLIENT_ON_ERROR(
      client, "Attempted to send after close frame was sent"
    );
    return;
  }
  if (TEST_FLAG(client, FLAG_CLIENT_CONNECTING))
  {
    LIBWSCLIENT_ON_ERROR(client, "Attempted to send during connect");
    return;
  }

  if (opcode == OP_CODE_TYPE_TEXT || opcode == OP_CODE_TYPE_BINARY)
  {
    if (!payload || payload_len == 0)
    {
      LIBWSCLIENT_ON_ERROR(client, "Payload data is empty");
      return;
    }
  }
  
  unsigned char frame_data[MAX_PAYLOAD_SIZE] = {0};
  int i, frame_count = ceil((float)payload_len / (float)MAX_PAYLOAD_PAD);
  if (frame_count == 0) frame_count = 1;

  for (i = 0; i < frame_count; i++) {
    uint64_t frame_size = i != frame_count - 1 ? MAX_PAYLOAD_PAD : payload_len % MAX_PAYLOAD_PAD;
    char op_code = i != 0 ? OP_CODE_CONTINUE : opcode;
    char fin = i != frame_count - 1 ? 0 : 1;
    memset(frame_data, 0, sizeof(frame_data));
    uint64_t frame_length = frame_size;
    int offset = 2;
    frame_data[0] |= (fin << 7) & 0x80;
    frame_data[0] |= op_code & 0xf;
    if (frame_size <= 125) {
      frame_data[1] = frame_size & 0x7f;
      frame_length += 2;
    } else if (frame_size >= 126 && frame_size <= 65535) {
      frame_data[1] = 126;
      frame_data[2] = (frame_size >> 8) & 255;
      frame_data[3] = (frame_size & 255);
      frame_length += 4;
      offset += 2;
    } else {
      frame_data[1] = 127;
      frame_data[2] = (unsigned char)((frame_size >> 56) & 255);
      frame_data[3] = (unsigned char)((frame_size >> 48) & 255);
      frame_data[4] = (unsigned char)((frame_size >> 40) & 255);
      frame_data[5] = (unsigned char)((frame_size >> 32) & 255);
      frame_data[6] = (unsigned char)((frame_size >> 24) & 255);
      frame_data[7] = (unsigned char)((frame_size >> 16) & 255);
      frame_data[8] = (unsigned char)((frame_size >> 8) & 255);
      frame_data[9] = (unsigned char)(frame_size & 255);
      frame_length += 10;
      offset += 8;
    }
    frame_data[1] |= 0x80;
    memcpy(frame_data + offset, &mask_int, 4);
    offset += 4;
    frame_length += 4;
    memcpy (frame_data + offset, &payload[i * MAX_PAYLOAD_PAD], frame_size);
    uint64_t n;
    for (n = 0; n < frame_size; n++) {
      frame_data[offset + n] ^= (frame_data[offset - 4 + n % 4] & 0xff);
    }
    frame_data[frame_length] = '\0';
    _libwsclient_write(client, frame_data, frame_length);
  }
}

void libwsclient_send_ping(wsclient *client, char *payload)
{
  libwsclient_send_data(
    client, OP_CODE_CONTROL_PING, (unsigned char*)payload, payload ? strlen(payload) : 0
  );
}
