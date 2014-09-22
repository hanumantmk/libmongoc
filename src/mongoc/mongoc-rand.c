/*
 * Copyright 2014 MongoDB, Inc.
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


#include "mongoc-config.h"

#include "mongoc-rand.h"
#include "mongoc-rand-private.h"

#ifdef MONGOC_ENABLE_SSL
# include <openssl/rand.h>
#else
# include "mongoc-thread-private.h"
#endif

int
_mongoc_rand (void)
{
   int x, r;

   r = _mongoc_rand_pseudo_bytes ((uint8_t *)&x, sizeof (x));

   BSON_ASSERT (r != -1);

   return x;
}

#ifdef MONGOC_ENABLE_SSL

int
_mongoc_rand_bytes (uint8_t *buf,
                    int      num)
{
   return RAND_bytes (buf, num);
}

int
_mongoc_rand_pseudo_bytes (uint8_t *buf,
                           int      num)
{
   return RAND_pseudo_bytes (buf, num);
}

void
mongoc_rand_seed (const void *buf,
                  int         num)
{
   RAND_seed (buf, num);
}

void
mongoc_rand_add (const void *buf,
                 int         num,
                 double      entropy)
{
   RAND_add (buf, num, entropy);
}

int
mongoc_rand_status (void)
{
   return RAND_status ();
}

#else

#ifndef MONGOC_OS_WIN32
mongoc_mutex_t gMongocRandMutex = MONGOC_MUTEX_INITIALIZER;
uint32_t gMongocRandSeed = 1;
#endif

int
_mongoc_rand_bytes (uint8_t *buf,
                    int      num)
{
   return -1;
}

int
_mongoc_rand_pseudo_bytes (uint8_t *buf,
                           int      num)
{
   int r;
   int written;

#ifndef MONGOC_OS_WIN32
   mongoc_mutex_lock (&gMongocRandMutex);
#endif

   for (written = 0; written < num; written += 4) {
#ifdef MONGOC_OS_WIN32
      r = rand ();
#else
      r = rand_r (&gMongocRandSeed);
#endif

      memcpy (buf + written, &r, MIN (num - written, 4));
   }

#ifndef MONGOC_OS_WIN32
   mongoc_mutex_unlock (&gMongocRandMutex);
#endif

   return 0;
}

void
mongoc_rand_seed (const void *buf,
                  int         num)
{
   int written;
   uint32_t seed = 0;
   uint32_t pad = 0;

   for (written = 0; written < num; written += 4) {
      memcpy (&pad, buf + written, MIN (num - written, 4));

      seed ^= pad;
   }

#ifdef MONGOC_OS_WIN32
   srand (seed);
#else
   mongoc_mutex_lock (&gMongocRandMutex);
   gMongocRandSeed = seed;
   mongoc_mutex_unlock (&gMongocRandMutex);
#endif
}

void
mongoc_rand_add (const void *buf,
                 int         num,
                 double      entropy)
{
   mongoc_rand_seed (buf, num);
}

int
mongoc_rand_status (void)
{
   return 0;
}

#endif
