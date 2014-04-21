#include "mongoc-proxy-private.h"

#include "bcon.h"
#include "uthash.h"
#include "utlist.h"

#include "mongoc-uri.h"
#include "mongoc-rpc-private.h"
#include "mongoc-buffer-private.h"
#include "mongoc-counters-private.h"
#include "mongoc-matcher.h"
#include "mongoc-opcode.h"
#include "mongoc-socket.h"
#include "mongoc-error.h"
#include "mongoc-flags.h"
#include "mongoc-trace.h"
#include "mongoc-stream-private.h"
#include "mongoc-stream-socket.h"
#include "mongoc-thread-private.h"
#include "mongoc-util-private.h"
#include "mongoc-write-concern-private.h"

#define MONGOC_PROXY_CMD_HANDLER_DEFAULTS 6
#define MONGOC_PROXY_DEFAULT_BATCH 20

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_ping(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "pong", BCON_BOOL(true)
    );
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_isMaster(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "ismaster", BCON_BOOL(true)
    );
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_whatsmyuri(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "you", "0.0.0.0"
    );
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_replSetGetStatus(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "ok", BCON_INT32(0),
        "errmsg", "not running with --replSet"
    );
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_getLog(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "ok", BCON_INT32(1),
        "totalLinesWritten", BCON_INT32(0),
        "log", "[", "]"
    );
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_cmd_dispatch_shutdown(mongoc_proxy_t * proxy, const bson_t * cmd)
{
    fprintf(stderr, "got shutdown\n");
    mongoc_mutex_lock(&proxy->mutex);
    proxy->keep_going = false;
    mongoc_mutex_unlock(&proxy->mutex);

    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "ok", BCON_INT32(1)
    );
}

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

   proxy = conn->proxy;

   bson_return_val_if_fail (proxy, false);
   bson_return_val_if_fail (rpc, false);
   bson_return_val_if_fail (buffer, false);

   /*
    * Buffer the message length to determine how much more to read.
    */
   pos = buffer->len;

   if (!_mongoc_buffer_append_from_stream (buffer, conn->stream, 4,
                                           proxy->sockettimeoutms, error)) {
      RETURN (false);
   }

   /*
    * Read the msg length from the buffer.
    */
   memcpy (&msg_len, &buffer->data[buffer->off + pos], 4);
   msg_len = BSON_UINT32_FROM_LE (msg_len);

   if ((msg_len < 16) || (msg_len > proxy->max_bson_size)) {
      RETURN (false);
   }

   /*
    * Read the rest of the message from the stream.
    */
   if (!_mongoc_buffer_append_from_stream (buffer, conn->stream, msg_len - 4,
                                           proxy->sockettimeoutms, error)) {
      RETURN (false);
   }

   /*
    * Scatter the buffer into the rpc structure.
    */
   if (!_mongoc_rpc_scatter (rpc, &buffer->data[buffer->off + pos], msg_len)) {
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
   int on = 1;

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
       fprintf(stderr, "Failed to resolve\n");
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
       * Turn on reuseaddr
       */
      if (0 != mongoc_socket_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, 4)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }


      /*
       * Try to bind to the address
       */
      if (0 != mongoc_socket_bind (sock,
                                   rp->ai_addr,
                                   (socklen_t)rp->ai_addrlen)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }

      /*
       * Try to listen
       */
      if (0 != mongoc_socket_listen(sock, 1024)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }

      break;
   }

   if (!sock) {
       fprintf(stderr, "failed to bind a socket\n");
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
    _mongoc_array_init(&conn->iov, sizeof(struct iovec));

    return conn;
}

static void
_mongoc_proxy_conn_destroy (mongoc_proxy_conn_t * conn)
{
    mongoc_stream_destroy(conn->stream);
    _mongoc_array_destroy(&conn->iov);
    mongoc_thread_join(conn->thread);
    bson_free(conn);
}

static bool
_mongoc_proxy_extract_bson(bson_t * bson, const uint8_t * buf)
{
    bool r;

    uint32_t len;

    memcpy(&len, buf, 4);
    len = BSON_UINT32_FROM_LE(len);

    r = bson_init_static(bson, buf, len);

    {
        char * ugh = bson_as_json(bson, NULL);
        free(ugh);
    }

    return r;
}

static void
_mongoc_proxy_conn_cursor_send (mongoc_proxy_conn_t   *conn,
                                mongoc_proxy_cursor_t *cursor,
                                int32_t                n_return,
                                int32_t                response_to)
{
    mongoc_rpc_t rpc;
    mongoc_proxy_t * proxy;
    int32_t req_id;
    bson_writer_t * writer;
    uint8_t * buf = NULL;
    size_t buflen = 0;
    int32_t to_send;
    int32_t sent = 0;
    bool more;
    bson_t * bson;

    writer = bson_writer_new(&buf, &buflen, 0, bson_realloc_ctx, NULL);

    proxy = conn->proxy;

    mongoc_mutex_lock(&proxy->mutex);
    req_id = proxy->request_id_seq++;
    mongoc_mutex_unlock(&proxy->mutex);

    rpc.reply.opcode = MONGOC_OPCODE_REPLY;
    rpc.reply.flags = MONGOC_REPLY_AWAIT_CAPABLE;
    rpc.reply.request_id = req_id;
    rpc.reply.response_to = response_to;
    rpc.reply.start_from = cursor->pos;

    if (! n_return) {
        to_send = MONGOC_PROXY_DEFAULT_BATCH;
    } else if (n_return > 0) {
        to_send = n_return;
    } else {
        to_send = n_return * -1;
    }
    more = true;

    while (to_send && more) {
        bson_writer_begin(writer, &bson);
        more = cursor->handler.yield(cursor->data, bson);
        bson_writer_end(writer);

        sent++;
        to_send--;
    }

    if ((! more) || n_return < 0) {
        rpc.reply.cursor_id = 0;
    } else {
        rpc.reply.cursor_id = cursor->id;
    }

    rpc.reply.documents = buf;
    rpc.reply.documents_len = bson_writer_get_length(writer);
    rpc.reply.n_returned = sent;

    _mongoc_proxy_conn_sendv(conn, &rpc, 1, NULL);

    bson_writer_destroy(writer);
    bson_free(buf);
}

static mongoc_proxy_cursor_t *
_mongoc_proxy_handle_cmd (mongoc_proxy_t *proxy,
                          const bson_t   *bson,
                          mongoc_rpc_t   *rpc)
{
    mongoc_proxy_cursor_t * cursor = NULL;
    bool matched = false;
    int i;

    for (i = 0; i < proxy->n_cmd_dispatch; i++) {
        if (mongoc_matcher_match(proxy->cmd_dispatch[i].matcher, bson)) {
            matched = true;
            cursor = proxy->cmd_dispatch[i].cb(proxy, bson);
            break;
        }
    }

    if (! matched) {
        char * json = bson_as_json(bson, NULL);

        fprintf(stderr, "unknown command: %s\n", json);
        bson_free(json);
    }

    return cursor;
}

static void *
_mongoc_proxy_conn_loop(void * _conn)
{
    mongoc_proxy_conn_t * conn = (mongoc_proxy_conn_t *)_conn;
    bool keep_going = true;
    mongoc_proxy_t * proxy = conn->proxy;
    mongoc_rpc_t rpc;
    mongoc_buffer_t buffer;
    bson_error_t error;
    mongoc_proxy_cursor_t * cursor;
    bson_t bsons[2];
    bool r;

    _mongoc_buffer_init(&buffer, NULL, 0, bson_realloc_ctx);

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
                    _mongoc_proxy_extract_bson(bsons, rpc.query.query);
                    if (rpc.query.fields)
                    _mongoc_proxy_extract_bson(bsons + 1, rpc.query.fields);

                    if (strcmp(strchr(rpc.query.collection, '.'), ".$cmd") == 0) {
                        cursor = _mongoc_proxy_handle_cmd(proxy, bsons, &rpc);
                    } else {
                        cursor = proxy->handler.op_query (
                           proxy,
                           proxy->data,
                           rpc.query.flags, rpc.query.collection,
                           rpc.query.skip, rpc.query.n_return,
                           bsons,
                           bsons + 1
                        );
                    }

                    if (cursor) {
                        _mongoc_proxy_conn_cursor_send(conn, cursor, rpc.query.n_return, rpc.query.request_id);
                    }
                    break;
                }

                case MONGOC_OPCODE_GET_MORE: {
                    mongoc_mutex_lock(&proxy->mutex);
                    HASH_FIND(hh, proxy->cursors, &rpc.get_more.cursor_id, 8, cursor);
                    mongoc_mutex_unlock(&proxy->mutex);

                    if (cursor) {
                        mongoc_mutex_lock(&cursor->mutex);
                        _mongoc_proxy_conn_cursor_send(conn, cursor, rpc.get_more.n_return, rpc.get_more.request_id);
                        mongoc_mutex_unlock(&cursor->mutex);
                    }
                    break;
                }

                default:
                    fprintf(stderr, "Got request: %d\n", rpc.header.opcode);
            }
        }
    }

    _mongoc_buffer_destroy(&buffer);

    return NULL;
}

static void *
_mongoc_proxy_loop(void * _proxy)
{
    mongoc_proxy_t * proxy = (mongoc_proxy_t *)_proxy;
    mongoc_socket_t * socket;
    mongoc_proxy_conn_t * conn;
    bool keep_going;
    int64_t expire_at;

    for (;;) {
        mongoc_mutex_lock(&proxy->mutex);
        keep_going = proxy->keep_going;
        mongoc_mutex_unlock(&proxy->mutex);
        if (! keep_going) {
            break;
        }

        expire_at = bson_get_monotonic_time() + proxy->sockettimeoutms;

        socket = mongoc_socket_accept(proxy->socket, expire_at);

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

static mongoc_proxy_cmd_dispatch_t *
_mongoc_proxy_cmd_dispatch_new (const mongoc_proxy_cmd_handler_t *cmd_handler,
                                size_t                            n_cmd_handler,
                                bson_error_t                     *error)
{
    int i;
    bson_t * match;
    mongoc_proxy_cmd_dispatch_t * cmd = bson_malloc0(sizeof(*cmd) * (n_cmd_handler + MONGOC_PROXY_CMD_HANDLER_DEFAULTS));

    for (i = 0; i < n_cmd_handler; i++) {
        cmd[i].matcher = mongoc_matcher_new(cmd_handler[i].match, error);
        cmd[i].cb = cmd_handler[i].cb;
    }

    match = BCON_NEW("isMaster", BCON_INT32(1));
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_isMaster;
    bson_destroy(match);

    match = BCON_NEW("getLog", "startupWarnings");
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_getLog;
    bson_destroy(match);

    match = BCON_NEW("replSetGetStatus", BCON_INT32(1));
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_replSetGetStatus;
    bson_destroy(match);

    match = BCON_NEW("whatsmyuri", BCON_INT32(1));
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_whatsmyuri;
    bson_destroy(match);

    match = BCON_NEW("shutdown", BCON_INT32(1));
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_shutdown;
    bson_destroy(match);

    match = BCON_NEW("ping", BCON_INT32(1));
    cmd[i].matcher = mongoc_matcher_new(match, error);
    cmd[i++].cb = _mongoc_proxy_cmd_dispatch_ping;
    bson_destroy(match);

    return cmd;
}


mongoc_proxy_t *
mongoc_proxy_new (const char                       *uri_string,
                  void                             *data,
                  const mongoc_proxy_handler_t     *handler,
                  const mongoc_proxy_cmd_handler_t *cmd_handler,
                  size_t                            n_cmd_handler,
                  bson_error_t                     *error)
{
    mongoc_uri_t * uri = mongoc_uri_new(uri_string);
    const mongoc_host_list_t *host = mongoc_uri_get_hosts(uri);

    mongoc_proxy_t * proxy = bson_malloc0(sizeof *proxy);
    mongoc_mutex_init(&proxy->mutex);
    proxy->max_bson_size = 1 << 24;
    proxy->max_msg_size = 1 << 24;
    memcpy(&proxy->handler, handler, sizeof *handler);
    proxy->data = data;
    proxy->socket = _mongoc_proxy_bind_tcp(host, error);
    proxy->sockettimeoutms = 2000;
    proxy->keep_going = true;

    proxy->cmd_dispatch = _mongoc_proxy_cmd_dispatch_new(cmd_handler, n_cmd_handler, error);
    proxy->n_cmd_dispatch = n_cmd_handler + MONGOC_PROXY_CMD_HANDLER_DEFAULTS;

    mongoc_uri_destroy(uri);

    mongoc_thread_create(&proxy->thread, _mongoc_proxy_loop, proxy);

    return proxy;
}

static void
_mongoc_proxy_cursor_destroy (mongoc_proxy_cursor_t * cursor)
{
    mongoc_mutex_destroy(&cursor->mutex);
    cursor->handler.destroy(cursor->data);
    bson_free(cursor);
}

void
mongoc_proxy_destroy (mongoc_proxy_t *proxy)
{
    mongoc_proxy_conn_t * conn, *conn_tmp;
    mongoc_proxy_cursor_t * cursor, *cursor_tmp;
    int i;
    mongoc_thread_join(proxy->thread);
    mongoc_mutex_destroy(&proxy->mutex);
    mongoc_socket_destroy(proxy->socket);

    for (i = 0; i < proxy->n_cmd_dispatch; i++) {
        mongoc_matcher_destroy(proxy->cmd_dispatch[i].matcher);
    }
    bson_free(proxy->cmd_dispatch);

    HASH_ITER(hh, proxy->cursors, cursor, cursor_tmp) {
        HASH_DELETE(hh, proxy->cursors, cursor);

        _mongoc_proxy_cursor_destroy(cursor);
    }

    DL_FOREACH_SAFE(proxy->connections, conn, conn_tmp) {
        DL_DELETE(proxy->connections, conn);
        _mongoc_proxy_conn_destroy(conn);
    }

    bson_free(proxy);
}

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new (mongoc_proxy_t                      *proxy,
                         void                                *data,
                         const mongoc_proxy_cursor_handler_t *handler)
{
    mongoc_proxy_cursor_t * cursor = bson_malloc0(sizeof *cursor);

    mongoc_mutex_init(&cursor->mutex);

    cursor->pos = 0;
    memcpy(&cursor->handler, handler, sizeof(*handler));
    cursor->data = data;

    mongoc_mutex_lock(&proxy->mutex);
    cursor->id = proxy->cursor_id_seq++;
    HASH_ADD_KEYPTR(hh, proxy->cursors, &cursor->id, 8, cursor);
    mongoc_mutex_unlock(&proxy->mutex);

    return cursor;
}

static void
_mongoc_proxy_cursor_new_from_bson_destroy (void   *_bson)
{
    bson_destroy((bson_t *)_bson);
}

static bool
_mongoc_proxy_cursor_new_from_bson_yield (void   *_src,
                                           bson_t *dest)
{
    const bson_t * src = (const bson_t *)_src;

    BCON_APPEND(dest, BCON(src));

    return false;
}

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson (mongoc_proxy_t *proxy,
                                   const bson_t   *bson)
{
    mongoc_proxy_cursor_handler_t handler;

    handler.yield = &_mongoc_proxy_cursor_new_from_bson_yield;
    handler.destroy = &_mongoc_proxy_cursor_new_from_bson_destroy;

    return mongoc_proxy_cursor_new(proxy, (void *)bson_copy(bson), &handler);
}


mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bcon (mongoc_proxy_t *proxy,
                                   ...) 
{
    mongoc_proxy_cursor_handler_t handler;
    bson_t * bson = bson_new();
    bcon_append_ctx_t ctx;
    va_list va;

    bcon_append_ctx_init(&ctx);

    va_start(va, proxy);
    bcon_append_ctx_va(bson, &ctx, &va);
    va_end(va);

    handler.yield = &_mongoc_proxy_cursor_new_from_bson_yield;
    handler.destroy = &_mongoc_proxy_cursor_new_from_bson_destroy;

    return mongoc_proxy_cursor_new(proxy, bson, &handler);
}


mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson_reader (mongoc_proxy_t      *proxy,
                                          const bson_reader_t *reader)
{
    return NULL;
}

