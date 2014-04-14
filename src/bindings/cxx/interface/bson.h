#pragma once

#include <stdint.h>
#include <iostream>

namespace mongo {
namespace ex {

template<class TBSON>
class BSON {
   public:
   TBSON impl;

   BSON(TBSON && b) : impl(b) {
       b.should_destroy = false;
   }

   const uint8_t * data() const {
      return impl.data();
   }

   uint32_t len() const {
      return impl.len();
   }

   operator bool() const {
      return impl.is_valid();
   }

   void print(std::ostream & out) const {
      impl.print(out);
   }
};

}
}

template<class TBSON>
inline std::ostream & operator<<(std::ostream & out, const mongo::ex::BSON<TBSON> & obj)
{
   obj.print(out);

   return out;
}
