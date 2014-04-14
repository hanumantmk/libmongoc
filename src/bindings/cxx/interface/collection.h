#pragma once

#include "interface/cursor.h"
#include "interface/bson.h"

#include <stdint.h>

namespace mongo {
namespace ex {

template<class TCollection, class TCursor, class TBSON>
class Collection {
   public:
    TCollection impl;

    Collection(TCollection && l) : impl(l) {
       l.should_destroy = false;
    }

    Cursor<TCursor, TBSON>
    find(uint32_t           skip,
         uint32_t           limit,
         uint32_t           batch_size,
         const BSON<TBSON> &query,
         const BSON<TBSON> &fields) {
       return Cursor<TCursor, TBSON>(impl.find(skip, limit, batch_size, query, fields));
    }
};

}
}
