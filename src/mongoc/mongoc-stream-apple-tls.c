/*
 * Copyright 2013 MongoDB, Inc.
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

#ifdef MONGOC_ENABLE_SSL
#ifdef MONGOC_APPLE_NATIVE_TLS

#include <bson.h>

#include <errno.h>
#include <string.h>

/* Use Apple SecureTransport */
#include <sys/mman.h>
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>

#include "mongoc-b64-private.h"
#include "mongoc-counters-private.h"
#include "mongoc-errno-private.h"
#include "mongoc-stream-apple-tls.h"
#include "mongoc-stream-private.h"
#include "mongoc-ssl-private.h"
#include "mongoc-ssl-apple-private.h"
#include "mongoc-trace.h"
#include "mongoc-log.h"

#undef MONGOC_LOG_DOMAIN
#define MONGOC_LOG_DOMAIN "stream-apple-tls"

/**
 * mongoc_stream_apple_tls_t:
 *
 * Private storage for handling callbacks from mongoc_stream and
 * SSLContextRef.
 *
 * The one funny wrinkle comes with timeout, which we use to
 * statefully pass timeouts through from the mongoc-stream api.
 *
 * TODO: is there a cleaner way to manage that?
 */
typedef struct
{
    mongoc_stream_t   parent;
    mongoc_stream_t  *base_stream;
    mongoc_ssl_apple_t ssl;
    int32_t           timeout_msec;
    bool              weak_cert_validation;
} mongoc_stream_apple_tls_t;

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_destroy --
 *
 *       Cleanup after usage of a mongoc_stream_apple_tls_t. Free all allocated
 *       resources and ensure connections are closed.
 *
 * Returns:
 *       None.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static void
_mongoc_stream_apple_tls_destroy (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   _mongoc_ssl_apple_destroy(&tls->ssl);

   mongoc_stream_destroy (tls->base_stream);
   tls->base_stream = NULL;

   bson_free (stream);

   mongoc_counter_streams_active_dec();
   mongoc_counter_streams_disposed_inc();
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_close --
 *
 *       Close the underlying socket.
 *
 *       Linus dictates that you should not check the result of close()
 *       since there is a race condition with EAGAIN and a new file
 *       descriptor being opened.
 *
 * Returns:
 *       0 on success; otherwise -1.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_apple_tls_close (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_close (tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_flush --
 *
 *       Flush the underlying stream.
 *
 * Returns:
 *       0 if successful; otherwise -1.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_apple_tls_flush (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_flush(tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_writev --
 *
 *       Write the iovec to the stream. This function will try to write
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, otherwise the number of bytes written.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static ssize_t
_mongoc_stream_apple_tls_writev (mongoc_stream_t *stream,
                                 mongoc_iovec_t  *iov,
                                 size_t           iovcnt,
                                 int32_t          timeout_msec)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
   OSStatus error;
   ssize_t ret = 0;
   size_t i;
   size_t iov_pos = 0;
   ssize_t write_ret;

   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {
         error = SSLWrite(tls->ssl.context,
                          iov[i].iov_base + iov_pos,
                          iov[i].iov_len - iov_pos,
                          (size_t *)&write_ret);

         if (noErr != error) {
            return -1;
         }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (write_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
                  errno = ETIMEDOUT;
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (expire - now) / 1000L;
            }
         }

         ret += write_ret;
         iov_pos += write_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_egress_add(ret);
   }

   return ret;
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_readv --
 *
 *       Read from the stream into iov. This function will try to read
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, 0 on EOF, otherwise the number of bytes read.
 *
 * Side effects:
 *       iov buffers will be written to.
 *
 *--------------------------------------------------------------------------
 */

static ssize_t
_mongoc_stream_apple_tls_readv (mongoc_stream_t *stream,
                                mongoc_iovec_t  *iov,
                                size_t           iovcnt,
                                size_t           min_bytes,
                                int32_t          timeout_msec)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
   OSStatus error;
   ssize_t ret = 0;
   size_t i;
   ssize_t read_ret;
   size_t iov_pos = 0;
   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {

         error = SSLRead(tls->ssl.context,
                         iov[i].iov_base + iov_pos,
                         iov[i].iov_len - iov_pos,
                         (size_t *)&read_ret);
         if (noErr != error) {
            return -1;
         }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (read_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
                  errno = ETIMEDOUT;
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (expire - now) / 1000L;
            }
         }

         ret += read_ret;

         if ((size_t)ret >= min_bytes) {
            mongoc_counter_streams_ingress_add(ret);
            return ret;
         }

         iov_pos += read_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_ingress_add(ret);
   }

   return ret;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_setsockopt --
 *
 *       Perform a setsockopt on the underlying stream.
 *
 * Returns:
 *       -1 on failure, otherwise opt specific value.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_apple_tls_setsockopt (mongoc_stream_t *stream,
                                     int              level,
                                     int              optname,
                                     void            *optval,
                                     socklen_t        optlen)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_setsockopt (tls->base_stream,
                                    level,
                                    optname,
                                    optval,
                                    optlen);
}

/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_apple_tls_do_handshake:
 *
 *        Force an ssl handshake.
 *        This will happen on the first read or write otherwise.
 *
 * Returns:
 *
 *        true for a successful handshake, false on error.
 *
 *--------------------------------------------------------------------------
 */

bool
mongoc_stream_apple_tls_do_handshake (mongoc_stream_t *stream,
                                      int32_t          timeout_msec)
{
   OSStatus error;
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   tls->timeout_msec = timeout_msec;

   error = SSLHandshake(tls->ssl.context);
   if (noErr == error) {
      return true;
   } else {
       fprintf(stderr, "err: %d\n", error);
   }

   if (!errno) {
      errno = ETIMEDOUT;
   }

   return false;
}


/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_apple_tls_check_cert:
 *
 *      Check the certificate returned by the other party.
 *
 *--------------------------------------------------------------------------
 */
bool
mongoc_stream_apple_tls_check_cert (mongoc_stream_t *stream,
                                    const char      *chost)
{
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

    return true;

    CFStringRef host = CFStringCreateWithCString(NULL, chost, kCFStringEncodingUTF8);

    SecTrustRef trust;
    SecPolicyRef policy_ref = SecPolicyCreateSSL(false, host);

    OSStatus ret = SSLCopyPeerTrust(tls->ssl.context, &trust);
    if(trust == NULL) {
//        failf(data, "SSL: error getting certificate chain");
        return false;
    }
    else if(ret != noErr) {
        //return sslerr_to_curlerr(data, ret);
        return false;
    }

    fprintf(stderr, "check cert: %d\n", __LINE__);
    ret = SecTrustSetPolicies(trust, policy_ref);
    if(ret != noErr) {
        return false;
    }
    fprintf(stderr, "check cert: %d\n", __LINE__);

    ret = SecTrustSetAnchorCertificates(trust, tls->ssl.anchor_certs);
    if(ret != noErr) {
        //return sslerr_to_curlerr(data, ret);
        return false;
    }
    fprintf(stderr, "check cert: %d\n", __LINE__);
    ret = SecTrustSetAnchorCertificatesOnly(trust, true);
    if(ret != noErr) {
        //return sslerr_to_curlerr(data, ret);
        return false;
    }
    fprintf(stderr, "check cert: %d\n", __LINE__);

    SecTrustResultType trust_eval = 0;
    ret = SecTrustEvaluate(trust, &trust_eval);
    CFRelease(trust);
    fprintf(stderr, "check cert: %d\n", __LINE__);
    if(ret != noErr) {
        //return sslerr_to_curlerr(data, ret);
        return false;
    }

    fprintf(stderr, "check cert: %d\n", __LINE__);
    fprintf(stderr, "check cert: trust_eval: %d\n", trust_eval);
    switch (trust_eval) {
        case kSecTrustResultUnspecified:
    fprintf(stderr, "check cert: %d\n", __LINE__);
        case kSecTrustResultProceed:
    fprintf(stderr, "check cert: %d\n", __LINE__);
            return true;

        case kSecTrustResultRecoverableTrustFailure:
    fprintf(stderr, "check cert: %d\n", __LINE__);
        case kSecTrustResultDeny:
    fprintf(stderr, "check cert: %d\n", __LINE__);
        default:
    fprintf(stderr, "check cert: %d\n", __LINE__);
//            failf(data, "SSL: certificate verification failed (result: %d)",
//                    trust_eval);
            return false;
    }
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_ssl_read --
 *
 *--------------------------------------------------------------------------
 */

static OSStatus
_mongoc_stream_apple_tls_ssl_read (SSLConnectionRef connection,
                                   void *data,
                                   size_t *data_length)
{
   // TODO this should sometimes return errors I think...
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)connection;
   mongoc_iovec_t iov;
   ssize_t read_length;

   iov.iov_base = data;
   iov.iov_len = *data_length;
   read_length = mongoc_stream_readv(tls->base_stream, &iov, 1,
                                     *data_length, tls->timeout_msec);
   fprintf(stderr, "log: %s:%d - %ld\n", __FILE__, __LINE__, read_length);

   *data_length = read_length;
   return noErr;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_ssl_write --
 *
 *--------------------------------------------------------------------------
 */

static OSStatus
_mongoc_stream_apple_tls_ssl_write (SSLConnectionRef connection,
                                    const void *data,
                                    size_t *data_length)
{
   // TODO this should sometimes return errors I think...
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)connection;
   mongoc_iovec_t iov;
   ssize_t write_length;

   iov.iov_base = (char *)data;
   iov.iov_len = *data_length;
   write_length = mongoc_stream_writev(tls->base_stream, &iov, 1,
                                       tls->timeout_msec);
   fprintf(stderr, "log: %s:%d - %ld\n", __FILE__, __LINE__, write_length);
   *data_length = write_length;
   return noErr;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_get_base_stream --
 *
 *       Return the underlying stream.
 *
 *--------------------------------------------------------------------------
 */

static mongoc_stream_t *
_mongoc_stream_apple_tls_get_base_stream (mongoc_stream_t *stream)
{
   return ((mongoc_stream_apple_tls_t *)stream)->base_stream;
}

/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_apple_tls_check_closed --
 *
 *       Check if the underlying stream is closed.
 *
 *--------------------------------------------------------------------------
 */

static bool
_mongoc_stream_apple_tls_check_closed (mongoc_stream_t *stream) /* IN */
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
   bson_return_val_if_fail(stream, -1);
   return mongoc_stream_check_closed (tls->base_stream);
}

/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_apple_tls_new --
 *
 *       Creates a new mongoc_stream_apple_tls_t to communicate with a remote
 *       server using a TLS stream.
 *
 *       @base_stream should be a stream that will become owned by the
 *       resulting tls stream. It will be used for raw I/O.
 *
 *       @trust_store_dir should be a path to the SSL cert db to use for
 *       verifying trust of the remote server.
 *
 * Returns:
 *       NULL on failure, otherwise a mongoc_stream_t.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

mongoc_stream_t *
mongoc_stream_apple_tls_new (mongoc_stream_t  *base_stream,
                             mongoc_ssl_opt_t *opt,
                             int               client)
{
   mongoc_stream_apple_tls_t *tls;

   BSON_ASSERT(base_stream);
   BSON_ASSERT(opt);

   tls = bson_malloc0 (sizeof *tls);
   tls->base_stream = base_stream;

   tls->parent.type = MONGOC_STREAM_APPLE_TLS; // yes?
   tls->parent.destroy = _mongoc_stream_apple_tls_destroy;
   tls->parent.close = _mongoc_stream_apple_tls_close;
   tls->parent.flush = _mongoc_stream_apple_tls_flush;
   tls->parent.writev = _mongoc_stream_apple_tls_writev;
   tls->parent.readv = _mongoc_stream_apple_tls_readv;

   tls->parent.setsockopt = _mongoc_stream_apple_tls_setsockopt;
   tls->parent.get_base_stream = _mongoc_stream_apple_tls_get_base_stream;
   tls->parent.check_closed = _mongoc_stream_apple_tls_check_closed;
   tls->weak_cert_validation = opt->weak_cert_validation;
   tls->timeout_msec = -1;

   _mongoc_ssl_apple_new(opt, &tls->ssl, client);

   /* custom SSL read/write functions */
   SSLSetIOFuncs(tls->ssl.context,
                 _mongoc_stream_apple_tls_ssl_read,
                 _mongoc_stream_apple_tls_ssl_write);

   SSLSetConnection(tls->ssl.context, tls);

   mongoc_counter_streams_active_inc();

   return (mongoc_stream_t *)tls;
}

#endif /* MONGOC_APPLE_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
