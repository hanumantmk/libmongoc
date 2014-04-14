#pragma once

#include "interface/cursor.h"
#include "interface/bson.h"
#include "interface/collection.h"

namespace mongo {
namespace ex {

template<class TClient, class TCursor, class TCollection, class TBSON>
class Client {
   public:
    TClient impl;

    Client(const char * uri) : impl(uri) {
    }

    Collection<TCollection, TCursor, TBSON>
    get_collection(const char * db, const char * collection) {
       return Collection<TCollection, TCursor, TBSON>(impl.get_collection(db, collection));
    }
};

}
}
