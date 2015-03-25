#include <mongoc.h>

#include "mongoc-topology-scanner-private.h"
#include "mock-server.h"
#include "mongoc-tests.h"
#include "TestSuite.h"

#include "test-libmongoc.h"

#undef MONGOC_LOG_DOMAIN
#define MONGOC_LOG_DOMAIN "topology-scanner-test"

#define TIMEOUT 5000
#define NSERVERS 10

#define TRUST_DIR "tests/trust_dir"
#define CAFILE TRUST_DIR "/verify/mongo_root.pem"
#define PEMFILE_NOPASS TRUST_DIR "/keys/mongodb.com.pem"

#ifdef _WIN32
static void
usleep (int64_t usec)
{
   HANDLE timer;
   LARGE_INTEGER ft;

   ft.QuadPart = -(10 * usec);

   timer = CreateWaitableTimer (NULL, true, NULL);
   SetWaitableTimer (timer, &ft, 0, NULL, NULL, 0);
   WaitForSingleObject (timer, INFINITE);
   CloseHandle (timer);
}
#endif

static bool
test_topology_scanner_helper (uint32_t      id,
                              const bson_t *bson,
                              int64_t       rtt_msec,
                              void         *data,
                              bson_error_t *error)
{
   int *finished = (int*)data;

   assert(bson);

   (*finished)--;

   return *finished >= NSERVERS ? true : false;
}

static void
test_topology_scanner(void)
{
   mock_server_t *servers[NSERVERS];
   mongoc_topology_scanner_t *topology_scanner;
   uint16_t port;
   int i;
   bson_t q = BSON_INITIALIZER;
   int finished = NSERVERS * 3;
   bool more_to_do;
   mongoc_host_list_t host = { 0 };

#ifdef MONGOC_ENABLE_SSL
   mongoc_ssl_opt_t sopt = { 0 };
   mongoc_ssl_opt_t copt = { 0 };
#endif

   port = 20000 + (rand () % 1000);

   topology_scanner = mongoc_topology_scanner_new (NULL, &test_topology_scanner_helper, &finished);

#ifdef MONGOC_ENABLE_SSL
   copt.ca_file = CAFILE;
   copt.weak_cert_validation = 1;

   mongoc_topology_scanner_set_ssl_opts (topology_scanner, &copt);
#endif

   for (i = 0; i < NSERVERS; i++) {
      servers[i] = mock_server_new ("127.0.0.1", port + i, NULL, NULL);
      mock_server_set_wire_version (servers[i], 0, i);

#ifdef MONGOC_ENABLE_SSL
      sopt.pem_file = PEMFILE_NOPASS;
      sopt.ca_file = CAFILE;

      mock_server_set_ssl_opts (servers[i], &sopt);
#endif

      mock_server_run_in_thread (servers[i]);

      bson_snprintf(host.host, sizeof(host.host), "127.0.0.1");
      bson_snprintf(host.host_and_port, sizeof(host.host_and_port), "127.0.0.1:%d", port + i);
      host.port = port + i;
      host.family = AF_INET;

      mongoc_topology_scanner_add(topology_scanner, &host, i);
   }

   usleep (5000);

   for (i = 0; i < 3; i++) {
      mongoc_topology_scanner_start (topology_scanner, TIMEOUT);

      more_to_do = mongoc_topology_scanner_work (topology_scanner, TIMEOUT);

      assert(! more_to_do);
   }

   assert(finished == 0);

   mongoc_topology_scanner_destroy (topology_scanner);

   bson_destroy (&q);

   for (i = 0; i < NSERVERS; i++) {
      mock_server_quit (servers[i], 0);
      mock_server_destroy (servers[i]);
   }
}

void
test_topology_scanner_install (TestSuite *suite)
{
   bool local;

   local = !getenv ("MONGOC_DISABLE_MOCK_SERVER");

   if (local) {
      TestSuite_Add (suite, "/TOPOLOGY/scanner", test_topology_scanner);
   }
}
