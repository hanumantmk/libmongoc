#include "mongo.h"

extern "C" {
#include "bcon.h"
}

#include <iostream>

int main(int argc, char ** argv)
{
   using namespace mongo;

   Client c("mongodb://localhost");

   Collection col = c.get_collection("test", "test");

   BSON query(BCON_NEW(
      "city", "new york"
   ));
   BSON fields(bson_new());

   Cursor cursor = col.find(0, 0, 0, query, fields);

   bool keep_going = true;

   while (keep_going) {
      const BSON & b = cursor.next();

      if (b) {
          std::cout << b << std::endl;
      } else {
          keep_going = false;
      }
   }

   return 0;
}
