#include "restclient.h"

#include <curl/curl.h>
#include <string.h>

typedef struct
{
   const char *data;
   size_t      len;
} restclient_buf_t;

typedef struct
{
   size_t len;
   size_t allocated;
   void  *data;
} restclient_realloc_buf_t;

struct restclient_response
{
   int                      code;
   restclient_realloc_buf_t body;
   restclient_realloc_buf_t error;
   bson_t                   headers;
   bson_t                   parsed_body;
};


static size_t
restclient_write_callback (void  *ptr,
                           size_t size,
                           size_t nmemb,
                           void  *userdata);

static size_t
restclient_header_callback (void  *ptr,
                            size_t size,
                            size_t nmemb,
                            void  *userdata);
static size_t
restclient_read_callback (void  *ptr,
                          size_t size,
                          size_t nmemb,
                          void  *userdata);
void
restclient_realloc_buf_init (restclient_realloc_buf_t *buf)
{
   buf->len = 0;
   buf->allocated = 128;
   buf->data = bson_malloc0 (buf->allocated);
}


void
restclient_realloc_buf_destroy (restclient_realloc_buf_t *buf)
{
   if (buf && buf->data) {
      bson_free (buf->data);
   }
}

void
restclient_realloc_buf_clear (restclient_realloc_buf_t *buf)
{
   buf->len = 0;
}

void
restclient_realloc_buf_append (restclient_realloc_buf_t *buf,
                               const void               *data,
                               size_t                    data_len)
{
   size_t len;
   size_t off;
   size_t next_size;

   bson_return_if_fail (buf);
   bson_return_if_fail (data);

   off = buf->len;
   len = data_len;

   if ((off + len) > buf->allocated) {
      next_size = bson_next_power_of_two (off + len);
      buf->data = bson_realloc (buf->data, next_size);
      buf->allocated = next_size;
   }

   memcpy ((uint8_t *)buf->data + off, data, len);

   buf->len += data_len;
}

static void
trim (restclient_buf_t *buf)
{
   while (isspace (buf->data[buf->len - 1]) && buf->len) {
      buf->len--;
   }

   while (isspace (buf->data[0] && buf->len)) {
      buf->len--;
      buf->data++;
   }
}

restclient_response_t *
restclient_response_new (void)
{
   restclient_response_t *response = bson_malloc0 (sizeof (*response));

   bson_init (&response->headers);
   bson_init (&response->parsed_body);
   restclient_realloc_buf_init (&response->body);
   restclient_realloc_buf_init (&response->error);

   return response;
}

int
restclient_response_code (restclient_response_t *response)
{
   return response->code;
}

const bson_t *
restclient_response_body (restclient_response_t *response)
{
   return &response->parsed_body;
}

const bson_t *
restclient_response_headers (restclient_response_t *response)
{
   return &response->headers;
}

void
restclient_response_destroy (restclient_response_t *response)
{
   restclient_realloc_buf_destroy (&response->body);
   restclient_realloc_buf_destroy (&response->error);
   bson_destroy (&response->headers);
   bson_destroy (&response->parsed_body);
}

const char *restclient_user_agent = "restclient/mongo-cxx-driver";

CURL *
restclient_curl_init (restclient_response_t *response,
                      const char            *url)
{
   CURL *curl = curl_easy_init ();

   if (curl) {
      curl_easy_setopt (curl, CURLOPT_USERAGENT, restclient_user_agent);
      curl_easy_setopt (curl, CURLOPT_URL, url);
      curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, restclient_write_callback);
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, response);
      curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION,
                        restclient_header_callback);
      curl_easy_setopt (curl, CURLOPT_HEADERDATA, response);
   }

   return curl;
}

void
restclient_curl_perform (CURL                  *curl,
                         restclient_response_t *response)
{
   CURLcode res = CURLE_OK;
   long http_code = 0;
   const char *errmsg = "Failed to curl.";
   bson_error_t error;

   res = curl_easy_perform (curl);

   if (res != CURLE_OK) {
      restclient_realloc_buf_append (&response->error, errmsg, strlen (
                                        errmsg) + 1);
      response->code = -1;
   } else {
      curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
      response->code = (int)http_code;
      restclient_realloc_buf_append (&response->body, "\0", 1);

      bson_destroy (&response->parsed_body);

      if (!bson_init_from_json (&response->parsed_body, response->body.data,
                                response->body.len, &error)) {
         response->code = -1;
         restclient_realloc_buf_append (&response->error, error.message, strlen (
                                           error.message) + 1);
      }
   }

   curl_easy_cleanup (curl);
   curl_global_cleanup ();
}

restclient_response_t *
restclient_get (const char *url)
{
   CURL *curl;

   restclient_response_t *response = restclient_response_new ();

   bson_init (&response->headers);

   if ((curl = restclient_curl_init (response, url))) {
      restclient_curl_perform (curl, response);
   }

   return response;
}

restclient_response_t *
restclient_post (const char   *url,
                 const bson_t *data)
{
   CURL *curl;
   restclient_response_t *response = restclient_response_new ();
   const char *ctype_header = "Content-Type: text/json";

   struct curl_slist *header = NULL;
   size_t json_len;
   char *json = bson_as_json (data, &json_len);

   if ((curl = restclient_curl_init (response, url))) {
      curl_easy_setopt (curl, CURLOPT_POST, 1L);
      curl_easy_setopt (curl, CURLOPT_POSTFIELDS, json);
      curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, json_len);
      header = curl_slist_append (header, ctype_header);
      curl_easy_setopt (curl, CURLOPT_HTTPHEADER, header);

      restclient_curl_perform (curl, response);

      curl_slist_free_all (header);
   }

   bson_free (json);

   return response;
}

restclient_response_t *
restclient_put (const char   *url,
                const bson_t *data)
{
   restclient_response_t *response = restclient_response_new ();
   const char *ctype_header = "Content-Type: text/json";
   size_t json_len;
   char *json = bson_as_json (data, &json_len);

   restclient_buf_t buf;
   CURL *curl;

   buf.data = json;
   buf.len = json_len;

   struct curl_slist *header = NULL;

   if ((curl = restclient_curl_init (response, url))) {
      curl_easy_setopt (curl, CURLOPT_PUT, 1L);
      curl_easy_setopt (curl, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt (curl, CURLOPT_READFUNCTION, restclient_read_callback);
      curl_easy_setopt (curl, CURLOPT_READDATA, &buf);
      curl_easy_setopt (curl, CURLOPT_INFILESIZE,
                        (long)buf.len);

      header = curl_slist_append (header, ctype_header);
      curl_easy_setopt (curl, CURLOPT_HTTPHEADER, header);

      restclient_curl_perform (curl, response);

      curl_slist_free_all (header);
   }

   bson_free (json);

   return response;
}

restclient_response_t *
restclient_del (const char *url)
{
   /** we want HTTP DELETE */
   const char *http_delete = "DELETE";
   restclient_response_t *response = restclient_response_new ();

   CURL *curl;

   if ((curl = restclient_curl_init (response, url))) {
      curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, http_delete);

      restclient_curl_perform (curl, response);
   }

   return response;
}

size_t
restclient_write_callback (void  *data,
                           size_t size,
                           size_t nmemb,
                           void  *userdata)
{
   restclient_response_t *r;

   r = (restclient_response_t *)userdata;
   restclient_realloc_buf_append (&r->body, data, size * nmemb);

   return size * nmemb;
}

size_t
restclient_header_callback (void  *data,
                            size_t size,
                            size_t nmemb,
                            void  *userdata)
{
   restclient_response_t *r;

   r = (restclient_response_t *)userdata;

   restclient_buf_t header;
   restclient_buf_t key;
   restclient_buf_t value;

   header.data = (const char *)data;
   header.len = size * nmemb;

   char *ptr;

   ptr = memchr (header.data, ':', header.len);

   if (ptr) {
      key.data = header.data;
      key.len = ptr - key.data;
      trim (&key);
      value.data = ptr + 1;
      value.len = header.len - (key.len + 1);

      bson_append_utf8 (&r->headers, key.data, key.len, value.data, value.len);
   } else {
      trim (&header);

      if (header.len) {
         bson_append_null (&r->headers, header.data, header.len);
      }
   }

   return size * nmemb;
}

size_t
restclient_read_callback (void  *data,
                          size_t size,
                          size_t nmemb,
                          void  *userdata)
{
   restclient_buf_t *u;

   u = (restclient_buf_t *)userdata;

   size_t curl_size = size * nmemb;
   size_t copy_size = (u->len < curl_size) ? u->len : curl_size;

   memcpy (data, u->data, copy_size);

   u->len -= copy_size;
   u->data += copy_size;

   return copy_size;
}
