#ifndef RESTCLIENT_H
#define RESTCLIENT_H

#include <bson.h>

typedef struct restclient_response restclient_response_t;

void
restclient_response_destroy (restclient_response_t *response);

int
restclient_response_code (restclient_response_t *response);

const bson_t *
restclient_response_body (restclient_response_t *response);

const bson_t *
restclient_response_headers (restclient_response_t *response);

restclient_response_t *
restclient_get (const char *url);

restclient_response_t *
restclient_post (const char   *url,
                 const bson_t *data);

restclient_response_t *
restclient_put (const char   *url,
                const bson_t *data);

restclient_response_t *
restclient_del (const char *url);

#endif
