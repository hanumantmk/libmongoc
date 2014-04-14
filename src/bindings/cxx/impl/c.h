#pragma once

#include "mongoc.h"
#include "bson.h"

namespace mongo {
namespace ex {
namespace c {

class BSON {
   public:
   bson_t * bson;
   bool should_destroy;

   BSON() : bson(NULL), should_destroy(false) {
   }

   BSON(bson_t * b) : bson(b), should_destroy(bson ? true : false) {
   }

   BSON(bson_t * b, bool sd) : bson(b), should_destroy(sd) {
   }

   const uint8_t * data() const {
      if (bson) {
         return bson_get_data(bson);
      } else {
         return NULL;
      }
   }

   uint32_t len() const {
      if (bson) {
         return bson->len;
      } else {
         return 0;
      }
   }

   ~BSON() {
      if (should_destroy) {
         bson_destroy(bson);
      }
   }

   bool is_valid() const {
      return bson != NULL;
   }

   void print(std::ostream & out) const {
      char * str;

      if (bson) {
         str = bson_as_json(bson, NULL);

         out << str;
         bson_free(str);
      } else {
         out << "NULL";
      }
   }
};

class Cursor {
   public:
   mongoc_cursor_t * cursor;
   ex::BSON<c::BSON> bson;
   bool should_destroy = true;

   Cursor(mongoc_cursor_t * c) : cursor(c), bson(c::BSON()) {
   }

   ~Cursor() {
      if (should_destroy) {
         mongoc_cursor_destroy(cursor);
      }
   }

   const ex::BSON<c::BSON> & next() {
      bool r;
      const bson_t * out;

      r = mongoc_cursor_next(cursor, &out);

      if (r) {
         bson = BSON((bson_t *)out, false);
      } else {
         bson = BSON();
      }

      return bson;
   }
};

class Collection {
   public:
   mongoc_collection_t * collection;
   bool should_destroy = true;

   Collection(mongoc_collection_t * c) : collection(c) {
   }

   ~Collection() {
      if (should_destroy) {
         mongoc_collection_destroy(collection);
      }
   }

   template<class TBSON>
   Cursor
   find(uint32_t           skip,
        uint32_t           limit,
        uint32_t           batch_size,
        const ex::BSON<TBSON> &query,
        const ex::BSON<TBSON> &fields) {
      bson_t _q, _f;

      bson_init_static(&_q, query.data(), query.len());
      bson_init_static(&_f, fields.data(), fields.len());

      return mongoc_collection_find(collection, MONGOC_QUERY_NONE, skip, limit, batch_size, &_q, &_f, NULL);
   }
};

class Client {
   public:
   mongoc_client_t * client;
   bool should_destroy = true;

   Client(const char * uri) : client(mongoc_client_new(uri)) {
   }

   ~Client() {
      if (should_destroy) {
         mongoc_client_destroy(client);
      }
   }

   Collection
   get_collection(const char * db, const char * collection) {
      return mongoc_client_get_collection(client, db, collection);
   }
};

}
}

typedef ex::Client<ex::c::Client, ex::c::Cursor, ex::c::Collection, ex::c::BSON> Client;
typedef ex::Cursor<ex::c::Cursor, ex::c::BSON> Cursor;
typedef ex::Collection<ex::c::Collection, ex::c::Cursor, ex::c::BSON> Collection;
typedef ex::BSON<ex::c::BSON> BSON;
}
