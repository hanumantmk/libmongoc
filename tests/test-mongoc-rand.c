#include <mongoc.h>

#include "mongoc-rand.h"
#include "mongoc-rand-private.h"

#include "TestSuite.h"

static void
test_mongoc_rand_add (void)
{
   uint8_t buf[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

   mongoc_rand_add (buf, sizeof (buf), 0.5);
}


static void
test_mongoc_rand_seed (void)
{
   uint8_t buf[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

   mongoc_rand_seed (buf, sizeof (buf));
}


static void
test_mongoc_rand_status (void)
{
   int x = mongoc_rand_status ();

   assert (x == 1 || x == 0);
}


static void
test_mongoc_rand_rand (void)
{
   uint8_t a[20] = { 0 };
   uint8_t b[20] = { 0 };
   int i, pad;

   for (i = 0; i < 20; i += 4) {
      pad = _mongoc_rand ();
      memcpy (a + i, &pad, 4);
      pad = _mongoc_rand ();
      memcpy (b + i, &pad, 4);
   }

   assert (memcmp (a, b, sizeof (a)) != 0);
}


static void
test_mongoc_rand_bytes (void)
{
   uint8_t a[20] = { 0 };
   uint8_t b[20] = { 0 };
   int x;

   x = _mongoc_rand_bytes (a, sizeof (a));
   _mongoc_rand_bytes (b, sizeof (b));

#ifdef MONGOC_ENABLE_SSL
   assert (x == 0 || x == 1);

   assert (memcmp (a, b, sizeof (a)) != 0);
#else
   assert (x == -1);
#endif
}

static void
test_mongoc_rand_pseudo_bytes (void)
{
   uint8_t a[20] = { 0 };
   uint8_t b[20] = { 0 };
   int x;

   x = _mongoc_rand_pseudo_bytes (a, sizeof (a));
   _mongoc_rand_pseudo_bytes (b, sizeof (b));

   assert (x == 0 || x == 1);

   assert (memcmp (a, b, sizeof (a)) != 0);
}

void
test_rand_install (TestSuite * suite)
{
   TestSuite_Add (suite, "/Rand/add", test_mongoc_rand_add);
   TestSuite_Add (suite, "/Rand/seed", test_mongoc_rand_seed);
   TestSuite_Add (suite, "/Rand/status", test_mongoc_rand_status);
   TestSuite_Add (suite, "/Rand/rand", test_mongoc_rand_rand);
   TestSuite_Add (suite, "/Rand/bytes", test_mongoc_rand_bytes);
   TestSuite_Add (suite, "/Rand/pseudo_bytes", test_mongoc_rand_pseudo_bytes);
}
