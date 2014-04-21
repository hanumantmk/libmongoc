#include <mongoc.h>
#include <bson.h>
#include <bcon.h>
#include "mongoc-thread-private.h"

mongoc_proxy_cursor_t *
query_handler (mongoc_proxy_t *proxy,
               void           *data,
               int32_t         flags,
               const char     *ns,
               int32_t         skip,
               int32_t         nreturn,
               const bson_t   *query,
               const bson_t   *fields)
{
    bson_t * bson = BCON_NEW("hello", "world");
    mongoc_proxy_cursor_t * cursor = mongoc_proxy_cursor_new_from_bson(proxy, bson);

    char * str = bson_as_json(query, NULL);
    fprintf(stderr, "BSON: %s, ns: %s\n", str, ns);
    free(str);

    bson_free(bson);

    return cursor;
}

mongoc_proxy_cursor_t *
magic_handler (mongoc_proxy_t *proxy, const bson_t * cmd)
{
    fprintf(stderr, "magic called!\n");

    return MONGOC_PROXY_CURSOR_NEW_FROM_BCON(proxy,
        "rand", BCON_INT32(rand())
    );
}

void *
run_client(void * _ignore)
{
    mongoc_client_t * client;
    bson_t * cmd, *query, *shutdown;
    bson_t reply = BSON_INITIALIZER;
    const bson_t * val;
    bson_error_t error;
    bool r;

    client = mongoc_client_new("mongodb://127.0.0.1:30000");

    cmd = BCON_NEW("magic", BCON_INT32(1));
    query = BCON_NEW("hi", "bye");
    shutdown = BCON_NEW("shutdown", BCON_DOUBLE(1));

    r = mongoc_client_command_simple(client, "admin", cmd, NULL, &reply, &error);

    if (! r) {
        fprintf(stderr, "errmsg: %s\n", error.message);
    }

    mongoc_collection_t * col = mongoc_client_get_collection(client, "test", "test");

    mongoc_cursor_t * cursor = mongoc_collection_find(col, 0, 0, 0, 0, query, NULL, NULL);

    while (mongoc_cursor_next(cursor, &val)) {
        char * json = bson_as_json(val, NULL);

        fprintf(stderr, "got: %s\n", json);

        bson_free(json);
    }

    mongoc_client_command_simple(client, "admin", shutdown, NULL, &reply, NULL);
    fprintf(stderr, "ran shutdown\n");

    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(col);
    mongoc_client_destroy(client);

    bson_destroy(&reply);
    bson_destroy(cmd);
    bson_destroy(shutdown);
    bson_destroy(query);

    return NULL;
}

void *
run_server(void * _ignore)
{
    mongoc_proxy_t * proxy;
    bson_error_t error;
    mongoc_proxy_handler_t handler;
    mongoc_proxy_cmd_handler_t * cmd_handler = malloc(sizeof(*cmd_handler) * 1);
    int i = 0;

    cmd_handler[i].match = BCON_NEW("magic", BCON_INT32(1));
    cmd_handler[i++].cb = magic_handler;

    handler.op_query = &query_handler;

    proxy = mongoc_proxy_new("mongodb://127.0.0.1:30000", NULL, &handler, cmd_handler, 1, &error);

    for (i = 0; i < 1; i++) {
        bson_destroy((bson_t *)cmd_handler[i].match);
    }

    bson_free(cmd_handler);

    mongoc_proxy_destroy(proxy);

    return NULL;
}

int main(int argc, char ** argv)
{
    mongoc_thread_t threads[2];

    mongoc_thread_create(threads + 0, run_server, NULL);

    sleep(1);

    mongoc_thread_create(threads + 1, run_client, NULL);

    int i;

    for (i = 0; i < 2; i++) {
        mongoc_thread_join(threads[i]);
    }

    return 0;
}
