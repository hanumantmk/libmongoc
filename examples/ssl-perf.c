/* gcc example.c -o example $(pkg-config --cflags --libs libmongoc-1.0) */

/* ./example-client [CONNECTION_STRING [COLLECTION_NAME]] */

#include <mongoc.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define N_THREADS 50
#define N_QUERIES 10000

static void *
test (void *data)
{
   mongoc_client_t *client;
   mongoc_collection_t *collection;
   mongoc_cursor_t *cursor;
   bson_error_t error;
   const bson_t *doc;
   char *uristr = (char *)data;
   const char *collection_name = "test";
   bson_t query;
   mongoc_ssl_opt_t ssl_opts = { 0 };
   int i;

   ssl_opts.weak_cert_validation = 1;
   client = mongoc_client_new (uristr);
   mongoc_client_set_ssl_opts (client, &ssl_opts);

   if (!client) {
      fprintf (stderr, "Failed to parse URI.\n");
      pthread_exit ((void *)1);
   }

   bson_init (&query);

   collection = mongoc_client_get_collection (client, "test", collection_name);

   for (i = 0; i < N_QUERIES; ++i) {
      cursor = mongoc_collection_find (collection,
                                       MONGOC_QUERY_NONE,
                                       0,
                                       0,
                                       0,
                                       &query,
                                       NULL,  /* Fields, NULL for all. */
                                       NULL); /* Read Prefs, NULL for default */

      while (mongoc_cursor_next (cursor, &doc)) {
      }

      if (mongoc_cursor_error (cursor, &error)) {
         fprintf (stderr, "Cursor Failure: %s\n", error.message);
         pthread_exit ((void *)1);
      }

      mongoc_cursor_destroy (cursor);
   }

   bson_destroy (&query);
   mongoc_collection_destroy (collection);
   mongoc_client_destroy (client);

   mongoc_cleanup ();

   pthread_exit (NULL);  /* Success. */
}

int
main (int   argc,
      char *argv[])
{
   int i;
   pthread_t threads[N_THREADS];
   clock_t start_time;
   double duration;

   if (argc < 2) {
      printf ("Usage: %s MONGODB_URI\n", argv[0]);
      exit (1);
   }

   mongoc_init ();

   for (i = 0; i < N_THREADS; ++i) {
      pthread_create (&threads[i], NULL, test, (void *)argv[1]);
   }

   start_time = clock ();

   for (i = 0; i < N_THREADS; ++i) {
      void *value;

      if (pthread_join (threads[i], &value) || value) {
         printf ("Thread %d errored.\n", i);
      }
   }

   duration = (double)(clock() - start_time) / CLOCKS_PER_SEC;
   printf ("%d queries on %d threads, %.2f seconds, %d qps\n",
           N_QUERIES, N_THREADS, duration,
           (int)((N_QUERIES * N_THREADS) / duration));

   return 0;
}
