#include <mongoc.h>
#include <bson.h>
#include <bcon.h>

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
    fprintf(stderr, "BSON: %s\n", str);
    free(str);

    bson_free(bson);

    return cursor;
}

int main(int argc, char ** argv)
{
    mongoc_proxy_t * proxy;
    bson_error_t error;
    mongoc_proxy_handler_t handler;

    handler.op_query = &query_handler;

    proxy = mongoc_proxy_new("mongodb://127.0.0.1:30000", NULL, &handler, &error);

    mongoc_proxy_destroy(proxy);

    return 0;
}
