/*
 * Copyright 2013 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef MONGOC_PROXY_PRIVATE_H
#define MONGOC_PROXY_PRIVATE_H


#include <bson.h>

#include "mongoc-array-private.h"
#include "mongoc-proxy.h"
#include "mongoc-stream.h"
#include "mongoc-thread-private.h"
#include "uthash.h"
#include "utlist.h"

BSON_BEGIN_DECLS

struct mongoc_proxy_cursor
{
   void   *data;
   int64_t id;

   mongoc_proxy_cursor_handler_t handler;

   UT_hash_handle hh;
};

typedef struct mongoc_proxy_conn
{
   mongoc_stream_t *stream;
   mongoc_thread_t  thread;
   mongoc_proxy_t  *proxy;
   mongoc_array_t   iov;
   int32_t          request_id;

   struct mongoc_proxy_conn *next, *prev;
} mongoc_proxy_conn_t;

struct mongoc_proxy
{
   mongoc_socket_t *socket;
   void            *data;
   int32_t          sockettimeoutms;
   int32_t          max_bson_size;
   int32_t          max_msg_size;
   mongoc_mutex_t   mutex;
   int64_t          cursor_id_seq;
   mongoc_thread_t  thread;
   bool             keep_going;

   mongoc_proxy_handler_t handler;

   mongoc_proxy_conn_t   *connections;
   mongoc_proxy_cursor_t *cursors;
};

BSON_END_DECLS


#endif /* MONGOC_PROXY_PRIVATE_H */
