#pragma once

#include "interface/bson.h"

namespace mongo {
namespace ex {

template<class TCursor, class TBSON>
class Cursor {
   public:
    TCursor impl;

    Cursor(TCursor && x) : impl(x) {
       x.should_destroy = false;
    }

    const BSON<TBSON> & next() {
        return impl.next();
    }
};

}
}
