#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <signal.h>
#include <stdbool.h>

#include <pthread.h>

#include "./include/libwsclient.h"
#include "wsclient.h"

#include "sha1.h"
#include "utils.h"

void * libwsclient_run_periodic(void * ptr)
{
  wsclient *c = (wsclient *)ptr;
  for (;;)
  {
    usleep(c->interval);
    c->onperiodic(c);
  }
  return NULL;
}

void *libwsclient_run_thread(void *ptr)
{
  wsclient *c = (wsclient *)ptr;
  size_t n;

  if (c->onperiodic && c->interval > 0)
  {
    pthread_create(
      &c->periodic_thread, NULL, libwsclient_run_periodic, (void *)c
    );
  }

  do
  {
    if (TEST_FLAG(c, FLAG_CLIENT_QUIT))
      break;
    unsigned char head[2] = {0};
    n = _libwsclient_read(c, head, 2);
    if (n < 2)
      break;

    // frame header
    bool fin = head[0] & 0x80;
    int op = head[0] & 0x0f;
    bool mask = head[1] & 0x80; // always false as it come from server.
    (void)mask;
    unsigned long long len = head[1] & 0x7f;
    if (len == 126)
    {
      uint16_t ulen = 0;
      n = _libwsclient_read(c, &ulen, 2);
      if (n < 2)
        break;
      len = ntohs(ulen);
    }
    else if (len == 127)
    {
      uint64_t ulen = 0;
      n = _libwsclient_read(c, &ulen, 8);
      if (n < 8)
        break;
      len = ntoh64(ulen);
    }

    wsclient_frame_in *pframe = calloc(sizeof(wsclient_frame_in), 1);
    pframe->fin = fin;
    pframe->opcode = op;
    pframe->payload_len = len;
    pframe->payload = calloc(len, 1);

    size_t z = 0;
    do
    {
      n = _libwsclient_read(c, pframe->payload + z, len - z);
      z += n;
    } while ((z < len) && (n > 0));

    if (z < len){
      char buff[128] = {0};
      sprintf(
        buff, "wsclient try to read %lld bytes, but get %ld bytes.", len, n
      );
      LIBWSCLIENT_ON_ERROR(c, buff);
      break;
    }

    handle_on_data_frame_in(c, pframe);

  } while (n > 0);

  if (!TEST_FLAG(c, FLAG_CLIENT_QUIT))
  {
    LIBWSCLIENT_ON_ERROR(c, "Error receiving data in client run thread");
  }

  if (c->onclose)
  {
    c->onclose(c);
  }
  close(c->sockfd);
  if (c->periodic_thread)
  {
    pthread_cancel(c->periodic_thread);
  }
  return NULL;
}


void libwsclient_handle_control_frame(wsclient *c, wsclient_frame_in *ctl_frame)
{
  // char mask[4];
  // int mask_int;
  // struct timeval tv;
  // gettimeofday(&tv, NULL);
  // srand(tv.tv_sec * tv.tv_usec);
  // mask_int = rand();
  // memcpy(mask, &mask_int, 4);
  switch (ctl_frame->opcode)
  {
  case OP_CODE_CONTROL_CLOSE:
#ifdef DEBUG
    // LIBWSCLIENT_ON_INFO(c, "websocket Received control --- Close.\n");
    if (ctl_frame->payload_len > 0)
    {
      char buff[1024] = {0};
      sprintf(
        buff, "websocket Receive control --- Close, len: %llu; code: %x,%x; reason: %s",
        ctl_frame->payload_len, ctl_frame->payload[0], ctl_frame->payload[1],
        ctl_frame->payload + 2
      );
      LIBWSCLIENT_ON_INFO(c, buff);
    }
#endif 
    if (!(TEST_FLAG(c, FLAG_CLIENT_CLOSEING)))
    {
      // server request close.  Send close frame as acknowledgement.
      libwsclient_send_data(
        c, OP_CODE_CONTROL_CLOSE, ctl_frame->payload, ctl_frame->payload_len
      );
      update_wsclient_status(c, FLAG_CLIENT_CLOSEING, 0);
    }
    break;
  case OP_CODE_CONTROL_PING:
#ifdef DEBUG
    LIBWSCLIENT_ON_INFO(c, "websocket Receive control---PING.\n");
#endif 
    libwsclient_send_data(
      c, OP_CODE_CONTROL_PONG, ctl_frame->payload, ctl_frame->payload_len
    );
    break;
  case OP_CODE_CONTROL_PONG:
#ifdef DEBUG
    LIBWSCLIENT_ON_INFO(c, "websocket Receive control---PONG.\n");
#endif 
    break;
  default:
    LIBWSCLIENT_ON_ERROR(c, "Unhandled control frame received.\n");
    break;
  }
}

inline void handle_on_data_frame_in(wsclient *c, wsclient_frame_in *pframe)
{
#ifdef DEBUG
  LIBWSCLIENT_ON_INFO(c, "websocket Receive data.\n");
#endif
  if (pframe->fin)
  {
    if (pframe->opcode == OP_CODE_CONTINUE)
    {
      pframe->prev_frame = c->current_frame;
      c->current_frame->next_frame = pframe;
      wsclient_frame_in *p = pframe;
      unsigned long long payload_len = p->payload_len;
      while (p->prev_frame)
      {
        p = p->prev_frame;
        payload_len += p->payload_len;
      }
      int op = p->opcode;
      unsigned char *payload = calloc(payload_len, 1);
      int offset = 0;
      memcpy(payload, p->payload, p->payload_len);
      offset += p->payload_len;
      while (p->next_frame)
      {
        free(p->payload);
        free(p);
        p = p->next_frame;
        memcpy(payload + offset, p->payload, p->payload_len);
        offset += p->payload_len;
      }
      free(p->payload);
      free(p);
      c->current_frame = NULL;

      if (c->onmessage)
        c->onmessage(c, op, payload_len, payload);
      free(payload);
    }
    else
    {
      if ((pframe->opcode & OP_CODE_CONTROL_CLOSE) == OP_CODE_CONTROL_CLOSE)
      {
        libwsclient_handle_control_frame(c, pframe);
      }
      else
      {
        if (c->onmessage)
          c->onmessage(c, pframe->opcode, pframe->payload_len, pframe->payload);
      }
      free(pframe->payload);
      free(pframe);
    }
  }
  else
  {
    if (c->current_frame == NULL)
      c->current_frame = pframe;
    else
    {
      c->current_frame->next_frame = pframe;
      pframe->prev_frame = c->current_frame;
      c->current_frame = pframe;
    }
  }
}

int libwsclient_open_connection(const char *host, const char *port)
{
  struct addrinfo hints, *servinfo, *p;
  int rv, sockfd;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
  {
    return 0;
  }

  for (p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      continue;
    }
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sockfd);
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo);
  if (p == NULL)
  {
    return 0;
  }
  return sockfd;
}

void *libwsclient_handshake_thread(void *ptr)
{
  wsclient *client = (wsclient *)ptr;
  const char *URI = client->URI;
  SHA1Context shactx;
  const char *UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  unsigned char sha1bytes[20] = {0};
  char websocket_key[256];
  unsigned char key_nonce[16] = {0};
  char scheme[10];
  char host[200];
  char request_host[256];
  char port[10];
  char path[255];
  char recv_buf[1024];
  char *URI_copy = NULL, *p = NULL, *rcv = NULL, *tok = NULL;
  int i, sockfd, n, flags = 0;
  URI_copy = (char *)malloc(strlen(URI) + 1);
  if (!URI_copy)
  {
    LIBWSCLIENT_ON_ERROR(client, "Unable to allocate memory in libwsclient_new.\n");
    return NULL;
  }
  memset(URI_copy, 0, strlen(URI) + 1);
  strncpy(URI_copy, URI, strlen(URI));
  p = strstr(URI_copy, "://");
  if (p == NULL)
  {
    LIBWSCLIENT_ON_ERROR(client, "Malformed or missing scheme for URI.\n");
    return NULL;
  }
  strncpy(scheme, URI_copy, p - URI_copy);
  scheme[p - URI_copy] = '\0';
  if (strcmp(scheme, "ws") != 0 && strcmp(scheme, "wss") != 0)
  {
    LIBWSCLIENT_ON_ERROR(client, "Invalid scheme for URI");
    return NULL;
  }
  if (strcmp(scheme, "ws") == 0)
  {
    strncpy(port, "80", 9);
  }
  else
  {
    strncpy(port, "443", 9);
    update_wsclient_status(client, FLAG_CLIENT_IS_SSL, 0);
  }
  size_t z = 0;
  for (
    i = p - URI_copy + 3, z = 0;
    *(URI_copy + i) != '/' && *(URI_copy + i) != ':' && *(URI_copy + i) != '\0';
    i++, z++
  )
  {
    host[z] = *(URI_copy + i);
  }
  host[z] = '\0';
  if (*(URI_copy + i) == ':')
  {
    i++;
    p = strchr(URI_copy + i, '/');
    if (!p)
      p = strchr(URI_copy + i, '\0');
    strncpy(port, URI_copy + i, (p - (URI_copy + i)));
    port[p - (URI_copy + i)] = '\0';
    i += p - (URI_copy + i);
  }
  if (*(URI_copy + i) == '\0')
  {
    // end of URI request path will be /
    strncpy(path, "/", 2);
  }
  else
  {
    strncpy(path, URI_copy + i, 254);
  }
  free(URI_copy);
  sockfd = libwsclient_open_connection(host, port);

  if (sockfd <= 0)
  {
    LIBWSCLIENT_ON_ERROR(client, "Error while getting address info");

    return NULL;
  }

  if (TEST_FLAG(client, FLAG_CLIENT_IS_SSL))
  {
    #ifdef HAVE_OPENSSL
    static bool b_ssl_need_inited = true;
    if (b_ssl_need_inited)
    {
      SSL_library_init();
      SSL_load_error_strings();
      b_ssl_need_inited = false;
    }
    client->ssl_ctx = SSL_CTX_new(SSLv23_method());
    client->ssl = SSL_new(client->ssl_ctx);
    SSL_set_fd(client->ssl, sockfd);
    SSL_connect(client->ssl);
    #else
    LIBWSCLIENT_ON_ERROR(client, "Error while setting ssl");
    return NULL;
    #endif
  }

  pthread_mutex_lock(&client->lock);
  client->sockfd = sockfd;
  pthread_mutex_unlock(&client->lock);
  // perform handshake
  // generate nonce
  srand(time(NULL));
  for (z = 0; z < 16; z++)
  {
    key_nonce[z] = rand() & 0xff;
  }
  base64_encode(key_nonce, 16, websocket_key, 256);

  if (strcmp(port, "80") != 0)
  {
    snprintf(request_host, 256, "%s:%s", host, port);
  }
  else
  {
    snprintf(request_host, 256, "%s", host);
  }
  char request_headers[1024] = {0};
  snprintf(
    request_headers, 1024, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\nHost: %s\r\nSec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n", path, request_host, websocket_key
  );
  n = _libwsclient_write(client, request_headers, strlen(request_headers));
  z = 0;
  memset(recv_buf, 0, 1024);
  // TODO: actually handle data after \r\n\r\n in case server
  //  sends post-handshake data that gets coalesced in this recv
  do
  {
    n = _libwsclient_read(client, recv_buf + z, 1);
    z += n;
  } while ((z < 4 || strstr(recv_buf, "\r\n\r\n") == NULL) && n > 0);

  if (n <= 0)
  {
    LIBWSCLIENT_ON_ERROR(client, "WS_HANDSHAKE_REMOTE_CLOSED_or_other_receive_ERR");
    return NULL;
  }

  // parse recv_buf for response headers and assure Accept matches expected value
  rcv = (char *)calloc(strlen(recv_buf) + 1, 1);
  if (!rcv)
  {
    LIBWSCLIENT_ON_ERROR(client, "Unable to allocate memory in libwsclient_new.\n");
    return NULL;
  }
  strncpy(rcv, recv_buf, strlen(recv_buf));

  char pre_encode[512] = {0};
  snprintf(pre_encode, 256, "%s%s", websocket_key, UUID);
  SHA1Reset(&shactx);
  SHA1Input(&shactx, (unsigned char*)pre_encode, strlen(pre_encode));
  SHA1Result(&shactx);
  memset(pre_encode, 0, 256);
  snprintf(
    pre_encode, sizeof(pre_encode) - 1, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0],
    shactx.Message_Digest[1], shactx.Message_Digest[2],
    shactx.Message_Digest[3], shactx.Message_Digest[4]
  );
  for (z = 0; z < (strlen(pre_encode) / 2); z++)
    sscanf(pre_encode + (z * 2), "%02hhx", sha1bytes + z);
  char expected_base64[512] = {0};
  base64_encode(sha1bytes, 20, expected_base64, 512);
  for (tok = strtok(rcv, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n"))
  {
    if (*tok == 'H' && *(tok + 1) == 'T' && *(tok + 2) == 'T' && *(tok + 3) == 'P')
    {
      p = strchr(tok, ' ');
      p = strchr(p + 1, ' ');
      *p = '\0';
      if (strcmp(tok, "HTTP/1.1 101") != 0 && strcmp(tok, "HTTP/1.0 101") != 0)
      {
        LIBWSCLIENT_ON_ERROR(
          client, "Remote web server responded with bad HTTP status during handshake"
        );
        LIBWSCLIENT_ON_INFO(client, "handshake resp: \n\t");
        LIBWSCLIENT_ON_INFO(client, rcv);

        return NULL;
      }
      flags |= FLAG_REQUEST_VALID_STATUS;
    }
    else
    {
      p = strchr(tok, ' ');
      *p = '\0';
      if (strcmp(tok, "Upgrade:") == 0)
      {
        if (stricmp(p + 1, "websocket") == 0)
        {
          flags |= FLAG_REQUEST_HAS_UPGRADE;
        }
      }
      if (strcmp(tok, "Connection:") == 0)
      {
        if (stricmp(p + 1, "upgrade") == 0)
        {
          flags |= FLAG_REQUEST_HAS_CONNECTION;
        }
      }
      if (strcmp(tok, "Sec-WebSocket-Accept:") == 0)
      {
        if (strcmp(p + 1, expected_base64) == 0)
        {
          flags |= FLAG_REQUEST_VALID_ACCEPT;
        }
      }
    }
  }
  if (!(flags & (
    FLAG_REQUEST_HAS_UPGRADE | FLAG_REQUEST_HAS_CONNECTION |
    FLAG_REQUEST_VALID_ACCEPT
  )))
  {
    LIBWSCLIENT_ON_ERROR(
      client, "Remote web server did not respond with expcet ( update, "
      "accept, connection) header during handshake"
    );
    return NULL;
  }
  // #ifdef DEBUG
  // LIBWSCLIENT_ON_INFO(client, "websocket handshake completed.\n");
  // #endif
  update_wsclient_status(client, 0, FLAG_CLIENT_CONNECTING);

  if (client->onopen != NULL)
  {
    client->onopen(client);
  }
  return NULL;
}

// somewhat hackish stricmp
int stricmp(const char *s1, const char *s2)
{
  register unsigned char c1, c2;
  register unsigned char flipbit = ~(1 << 5);
  do
  {
    c1 = (unsigned char)*s1++ & flipbit;
    c2 = (unsigned char)*s2++ & flipbit;
    if (c1 == '\0')
      return c1 - c2;
  } while (c1 == c2);
  return c1 - c2;
}

size_t _libwsclient_read(wsclient *c, void *buf, size_t length)
{
  size_t n = 0;
  ssize_t ret = -1;
  char * p = buf;
  #ifdef DEBUG
  char* sp = "";
  #endif
  for (; n < length; n++) {
    if (c->buf.pos == 0 || c->buf.pos == c->buf.len)
    {
      if (TEST_FLAG(c, FLAG_CLIENT_IS_SSL))
      {
        #ifdef DEBUG
        sp = "ssl";
        #endif
        #ifdef HAVE_OPENSSL
        ret = (ssize_t)SSL_read(
          c->ssl, (unsigned char *)c->buf.data, sizeof(c->buf.data)
        );
        #endif
      }
      else
      {
        ret = recv(
          c->sockfd, (unsigned char *)c->buf.data, sizeof(c->buf.data), 0
        );
      }
      if (ret <= 0)
      {
        if (ret < 0) c->buf.pos -= n;
        return ret;
      }
      c->buf.pos = 0;
      c->buf.len = (size_t)ret;
    }
    *(p++) = c->buf.data[c->buf.pos++];
  }
  #ifdef DEBUG
  char buff[256] = {0};
  sprintf(buff, "wsclient %s read %ld bytes.",sp, n);
  LIBWSCLIENT_ON_INFO(c, buff);
  c->onmessage(c, OP_CODE_TYPE_BINARY, n, buf);
  #endif
  return n;
}

size_t _libwsclient_write(wsclient *c, const void *buf, size_t length)
{
  pthread_mutex_lock(&c->send_lock);
  ssize_t len = 0;
  #ifdef DEBUG
  char* sp = "";
  #endif
  if (TEST_FLAG(c, FLAG_CLIENT_IS_SSL))
  {
    #ifdef DEBUG
    sp = "ssl";
    #endif
    #ifdef HAVE_OPENSSL
    len = (ssize_t) SSL_write(c->ssl, buf, length);
    #endif
  }
  else
  {
    #ifdef DEBUG
    sp = "";
    #endif
    len =  send(c->sockfd, buf, length, 0);
  }
  pthread_mutex_unlock(&c->send_lock);
  #ifdef DEBUG
  char buff[256] = {0};
  sprintf(buff, "wsclient %s send %ld of %ld bytes.",sp, len, length);
  LIBWSCLIENT_ON_INFO(c, buff);
  #endif
  return len;
}

void update_wsclient_status(wsclient *c, int add, int del)
{
  pthread_mutex_lock(&c->lock);
  if (add)
    c->flags |= add;
  if (del)
    c->flags &= ~del;
  pthread_mutex_unlock(&c->lock);
}
