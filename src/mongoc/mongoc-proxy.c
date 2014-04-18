#include "mongoc-proxy-private.h"

#include "mongoc-uri.h"
#include "mongoc-rpc-private.h"
#include "mongoc-buffer-private.h"
#include "mongoc-counters-private.h"
#include "mongoc-opcode.h"
#include "mongoc-socket.h"
#include "mongoc-error.h"
#include "mongoc-trace.h"
#include "mongoc-stream-private.h"
#include "mongoc-stream-socket.h"
#include "mongoc-thread-private.h"
#include "mongoc-util-private.h"
#include "mongoc-write-concern-private.h"

static bool
_mongoc_proxy_conn_recv (mongoc_proxy_conn_t *conn,
                         mongoc_rpc_t        *rpc,
                         mongoc_buffer_t     *buffer,
                         bson_error_t        *error)
{
   int32_t msg_len;
   off_t pos;
   mongoc_proxy_t *proxy;

   ENTRY;

   bson_return_val_if_fail (proxy, false);
   bson_return_val_if_fail (rpc, false);
   bson_return_val_if_fail (buffer, false);

   proxy = conn->proxy;

   /*
    * Buffer the message length to determine how much more to read.
    */
   pos = buffer->len;

   if (!_mongoc_buffer_append_from_stream (buffer, conn->stream, 4,
                                           proxy->sockettimeoutms, error)) {
      mongoc_counter_protocol_ingress_error_inc ();
      RETURN (false);
   }

   /*
    * Read the msg length from the buffer.
    */
   memcpy (&msg_len, &buffer->data[buffer->off + pos], 4);
   msg_len = BSON_UINT32_FROM_LE (msg_len);

   if ((msg_len < 16) || (msg_len > proxy->max_bson_size)) {
      bson_set_error (error,
                      MONGOC_ERROR_PROTOCOL,
                      MONGOC_ERROR_PROTOCOL_INVALID_REPLY,
                      "Corrupt or malicious request received.");
      mongoc_counter_protocol_ingress_error_inc ();
      RETURN (false);
   }

   /*
    * Read the rest of the message from the stream.
    */
   if (!_mongoc_buffer_append_from_stream (buffer, conn->stream, msg_len - 4,
                                           proxy->sockettimeoutms, error)) {
      mongoc_counter_protocol_ingress_error_inc ();
      RETURN (false);
   }

   /*
    * Scatter the buffer into the rpc structure.
    */
   if (!_mongoc_rpc_scatter (rpc, &buffer->data[buffer->off + pos], msg_len)) {
      bson_set_error (error,
                      MONGOC_ERROR_PROTOCOL,
                      MONGOC_ERROR_PROTOCOL_INVALID_REPLY,
                      "Failed to decode reply from server.");
      mongoc_counter_protocol_ingress_error_inc ();
      RETURN (false);
   }

   DUMP_BYTES (buffer, buffer->data + buffer->off, buffer->len);

   _mongoc_rpc_swab_from_le (rpc);

   RETURN (true);
}

static bool
_mongoc_proxy_conn_sendv (mongoc_proxy_conn_t *conn,
                          mongoc_rpc_t        *rpcs,
                          size_t               rpcs_len,
                          bson_error_t        *error)
{
   mongoc_iovec_t *iov;
   size_t iovcnt;
   size_t i;
   mongoc_proxy_t *proxy;

   ENTRY;

   bson_return_val_if_fail (conn, false);
   bson_return_val_if_fail (rpcs, false);
   bson_return_val_if_fail (rpcs_len, false);

   proxy = conn->proxy;

   BSON_ASSERT (conn->stream);

   _mongoc_array_clear (&conn->iov);

   for (i = 0; i < rpcs_len; i++) {
      rpcs[i].header.request_id = ++conn->request_id;
      _mongoc_rpc_gather (&rpcs[i], &conn->iov);

      if (rpcs[i].header.msg_len > (int32_t)proxy->max_msg_size) {
         bson_set_error (error,
                         MONGOC_ERROR_CLIENT,
                         MONGOC_ERROR_CLIENT_TOO_BIG,
                         "Attempted to send an RPC larger than the "
                         "max allowed message size. Was %u, allowed %u.",
                         rpcs[i].header.msg_len,
                         proxy->max_msg_size);
         RETURN (0);
      }

      _mongoc_rpc_swab_to_le (&rpcs[i]);
   }

   iov = conn->iov.data;
   iovcnt = conn->iov.len;
   errno = 0;

   DUMP_IOVEC (iov, iov, iovcnt);

   if (!mongoc_stream_writev (conn->stream, iov, iovcnt,
                              proxy->sockettimeoutms)) {
      char buf[128];
      char *errstr;
      errstr = bson_strerror_r (errno, buf, sizeof buf);

      bson_set_error (error,
                      MONGOC_ERROR_STREAM,
                      MONGOC_ERROR_STREAM_SOCKET,
                      "Failure during socket delivery: %s",
                      errstr);
      RETURN (0);
   }

   RETURN (true);
}


static mongoc_socket_t *
_mongoc_proxy_bind_tcp (const mongoc_host_list_t *host,
                        bson_error_t             *error)
{
   mongoc_socket_t *sock;
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   char portstr [8];
   int s;

   ENTRY;

   bson_return_val_if_fail (host, NULL);

   bson_snprintf (portstr, sizeof portstr, "%hu", host->port);

   memset (&hints, 0, sizeof hints);
   hints.ai_family = host->family;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   s = getaddrinfo (host->host, portstr, &hints, &result);

   if (s != 0) {
      bson_set_error(error,
                     MONGOC_ERROR_STREAM,
                     MONGOC_ERROR_STREAM_NAME_RESOLUTION,
                     "Failed to resolve %s",
                     host->host);
      RETURN (NULL);
   }

   for (rp = result; rp; rp = rp->ai_next) {
      /*
       * Create a new non-blocking socket.
       */
      if (!(sock = mongoc_socket_new (rp->ai_family,
                                      rp->ai_socktype,
                                      rp->ai_protocol))) {
         continue;
      }

      /*
       * Try to connect to the peer.
       */
      if (0 != mongoc_socket_bind (sock,
                                   rp->ai_addr,
                                   (socklen_t)rp->ai_addrlen)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }

      break;
   }

   if (!sock) {
      bson_set_error (error,
                      MONGOC_ERROR_STREAM,
                      MONGOC_ERROR_STREAM_CONNECT,
                      "Failed to bind to target host.");
      freeaddrinfo (result);
      RETURN (NULL);
   }

   freeaddrinfo (result);

   return sock;
}

static mongoc_proxy_conn_t *
_mongoc_proxy_conn_new (mongoc_proxy_t  *proxy,
                        mongoc_socket_t *socket)
{
    mongoc_proxy_conn_t * conn = bson_malloc0(sizeof *conn);

    conn->proxy = proxy;
    conn->stream = mongoc_stream_socket_new (socket);

    return conn;
}

static bool
_mongoc_array_append_bson(mongoc_array_t * array, const uint8_t * bson)
{
    bson_t buf;
    bool r;

    uint32_t len;

    memcpy(&len, bson, 4);
    len = BSON_UINT32_FROM_LE(len);

    r = bson_init_static(&buf, bson, len);

    if (r) {
        _mongoc_array_append_val(array, buf);
    }

    return r;
}

static void *
_mongoc_proxy_conn_loop(void * _conn)
{
    mongoc_proxy_conn_t * conn = (mongoc_proxy_conn_t *)_conn;
    bool keep_going;
    mongoc_proxy_t * proxy = conn->proxy;
    mongoc_rpc_t rpc;
    mongoc_buffer_t buffer;
    bson_error_t error;
    mongoc_proxy_cursor_t * cursor;
    mongoc_array_t bsons;
    bool r;

    _mongoc_buffer_init(&buffer, NULL, 0, bson_realloc_ctx);
    _mongoc_array_init(&bsons, sizeof(bson_t));

    while (keep_going) {
        mongoc_mutex_lock(&proxy->mutex);
        keep_going = proxy->keep_going;
        mongoc_mutex_unlock(&proxy->mutex);
        if (! keep_going) {
            break;
        }

        r = _mongoc_proxy_conn_recv(conn, &rpc, &buffer, &error);

        if (r) {
            switch (rpc.header.opcode) {
                case MONGOC_OPCODE_QUERY: {
                    _mongoc_array_append_bson(&bsons, rpc.query.query);
                    _mongoc_array_append_bson(&bsons, rpc.query.fields);
                    cursor = proxy->handler.op_query (
                       proxy,
                       proxy->data,
                       rpc.query.flags, rpc.query.collection,
                       rpc.query.skip, rpc.query.n_return,
                       &_mongoc_array_index (&bsons, bson_t, 0),
                       &_mongoc_array_index (&bsons, bson_t, 1)
                    );

                    _mongoc_proxy_cursor_send(cursor);
                }

                case MONGOC_OPCODE_GET_MORE:
                default:
                    keep_going = false;
            }
        } else {
            break;
        }
    }
    return NULL;
}

static void *
_mongoc_proxy_loop(void * _proxy)
{
    mongoc_proxy_t * proxy = (mongoc_proxy_t *)_proxy;
    mongoc_socket_t * socket;
    mongoc_proxy_conn_t * conn;
    bool keep_going;

    for (;;) {
        mongoc_mutex_lock(&proxy->mutex);
        keep_going = proxy->keep_going;
        mongoc_mutex_unlock(&proxy->mutex);
        if (! keep_going) {
            break;
        }

        socket = mongoc_socket_accept(proxy->socket, proxy->sockettimeoutms);

        if (socket) {
            conn = _mongoc_proxy_conn_new(proxy, socket);

            mongoc_mutex_lock(&proxy->mutex);

            DL_APPEND(proxy->connections, conn);

            mongoc_mutex_unlock(&proxy->mutex);

            mongoc_thread_create(&conn->thread, _mongoc_proxy_conn_loop, conn);
        }
    }

    return NULL;
}

mongoc_proxy_t *
mongoc_proxy_new (const char                   *uri_string,
                  void                         *data,
                  const mongoc_proxy_handler_t *handler,
                  bson_error_t                 *error)
{
    mongoc_uri_t * uri = mongoc_uri_new(uri_string);
    const mongoc_host_list_t *host = mongoc_uri_get_hosts(uri);

    mongoc_proxy_t * proxy = bson_malloc0(sizeof *proxy);

    memcpy(&proxy->handler, handler, sizeof *handler);
    proxy->data = data;
    proxy->socket = _mongoc_proxy_bind_tcp(host, error);

    mongoc_uri_destroy(uri);

    mongoc_thread_create(&proxy->thread, _mongoc_proxy_loop, proxy);

    return proxy;
}

void
mongoc_proxy_destroy (mongoc_proxy_t *proxy)
{
    bson_free(proxy);
}

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new (mongoc_proxy_t                      *proxy,
                         void                                *data,
                         const mongoc_proxy_cursor_handler_t *handler)
{
    mongoc_proxy_cursor_t * cursor = bson_malloc0(sizeof *cursor);

    return cursor;
}

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson (mongoc_proxy_t *proxy,
                                   const bson_t   *bson)
{
    mongoc_proxy_cursor_t * cursor = bson_malloc0(sizeof *cursor);

    return cursor;
}


mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson_reader (mongoc_proxy_t      *proxy,
                                          const bson_reader_t *reader)
{
    mongoc_proxy_cursor_t * cursor = bson_malloc0(sizeof *cursor);

    return cursor;
}

