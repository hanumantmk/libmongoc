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


#ifndef MONGOC_PROXY_H
#define MONGOC_PROXY_H


#include <bson.h>

BSON_BEGIN_DECLS

typedef struct mongoc_proxy_cursor mongoc_proxy_cursor_t;
typedef struct mongoc_proxy mongoc_proxy_t;

typedef struct
{
   bool (*yield)(void   *data,
                 bson_t *bson);

   void (*destroy)(void *data);
} mongoc_proxy_cursor_handler_t;

typedef struct
{
   mongoc_proxy_cursor_t * (*op_query)(mongoc_proxy_t *proxy,
                                       void           *data,
                                       int32_t         flags,
                                       const char     *ns,
                                       int32_t         skip,
                                       int32_t         nreturn,
                                       const bson_t   *query,
                                       const bson_t   *fields);

   bool (*op_update)(mongoc_proxy_t *proxy,
                     void           *data,
                     const char     *ns,
                     int32_t         flags,
                     const bson_t   *selector,
                     const bson_t   *update);

   bool (*op_insert)(mongoc_proxy_t *proxy,
                     void           *data,
                     int32_t         flags,
                     const char     *ns,
                     const bson_t  **documents,
                     int32_t         n_documents);

   bool (*op_delete)(mongoc_proxy_t *proxy,
                     void           *data,
                     const char     *ns,
                     int32_t         flags,
                     const bson_t   *selector);

   bool (*op_padding[5]) (void);

   void (*destroy)(void *data);
} mongoc_proxy_handler_t;

mongoc_proxy_t *
mongoc_proxy_new (const char                   *uri_string,
                  void                         *data,
                  const mongoc_proxy_handler_t *handler,
                  bson_error_t                 *error);

void
mongoc_proxy_destroy (mongoc_proxy_t *proxy);

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new (mongoc_proxy_t                      *proxy,
                         void                                *data,
                         const mongoc_proxy_cursor_handler_t *handler);

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson (mongoc_proxy_t *proxy,
                                   const bson_t   *bson);

mongoc_proxy_cursor_t *
mongoc_proxy_cursor_new_from_bson_reader (mongoc_proxy_t      *proxy,
                                          const bson_reader_t *reader);

BSON_END_DECLS


#endif /* MONGOC_PROXY_H */
