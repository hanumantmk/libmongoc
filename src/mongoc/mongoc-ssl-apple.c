/*
 * Copyright 2015 MongoDB, Inc.
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

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
#include <stdio.h>
#include <sys/mman.h>

#include "mongoc-b64-private.h"
#include "mongoc-ssl-apple-private.h"
#include "mongoc-log.h"

CFStringRef
_mongoc_ssl_apple_copy_cert_subject (SecCertificateRef cert)
{
   CFStringRef server_cert_summary = CFSTR ("(null)");

#if TARGET_OS_EMBEDDED || TARGET_OS_IPHONE
   /* iOS: There's only one way to do this. */
   server_cert_summary = SecCertificateCopySubjectSummary (cert);
#else
#if MAC_OS_X_VERSION_MAX_ALLOWED < 1070

   /* Lion & later: Get the long description if we can. */
   if (SecCertificateCopyLongDescription != NULL) {
      server_cert_summary =
         SecCertificateCopyLongDescription (NULL, cert, NULL);
   } else
#endif /* 10.7 */
#if MAC_OS_X_VERSION_MAX_ALLOWED < 1060

   /* Snow Leopard: Get the certificate summary. */
   if (SecCertificateCopySubjectSummary != NULL) {
      server_cert_summary = SecCertificateCopySubjectSummary (cert);
   } else
#endif /* 10.6 */
   /* Leopard is as far back as we go... */
   (void)SecCertificateCopyCommonName (cert, &server_cert_summary);
#endif
   return server_cert_summary;
}

static bool
_mongoc_ssl_apple_load_identity (SSLContextRef ssl,
                                 const char   *label)
{
   SecIdentityRef cert_and_key = NULL;
   OSStatus status = errSecItemNotFound;

   /* SecItemCopyMatching() was introduced in iOS and Snow Leopard.
    * kSecClassIdentity was introduced in Lion. If both exist, let's use them
    * to find the certificate. */
   if (SecItemCopyMatching != NULL && kSecClassIdentity != NULL) {
      CFTypeRef keys[4];
      CFTypeRef values[4];
      CFDictionaryRef query_dict;
      CFStringRef label_cf = CFStringCreateWithCString (NULL, label,
                                                        kCFStringEncodingUTF8);

      /* Set up our search criteria and expected results: */
      values[0] = kSecClassIdentity; /* we want a certificate and a key */
      keys[0] = kSecClass;
      values[1] = kCFBooleanTrue;  /* we want a reference */
      keys[1] = kSecReturnRef;
      values[2] = kSecMatchLimitOne; /* one is enough, thanks */
      keys[2] = kSecMatchLimit;
      /* identity searches need a SecPolicyRef in order to work */
      values[3] = SecPolicyCreateSSL (false, label_cf);
      keys[3] = kSecMatchPolicy;
      query_dict = CFDictionaryCreate (NULL, (const void **)keys,
                                       (const void **)values, 4L,
                                       &kCFCopyStringDictionaryKeyCallBacks,
                                       &kCFTypeDictionaryValueCallBacks);
      CFRelease (values[3]);
      CFRelease (label_cf);

      /* Do we have a match? */
      status = SecItemCopyMatching (query_dict, (CFTypeRef *)&cert_and_key);

      if (status) {
         MONGOC_WARNING ("Failed to locate native identity: %s\n", label);
      }

      CFRelease (query_dict);
   } else {
      return false;
   }

   if (status == noErr) {
      SecCertificateRef cert = NULL;
      CFTypeRef certs_c[1];
      CFArrayRef certs = NULL;

      /* If we found one, print it out: */
      status = SecIdentityCopyCertificate (cert_and_key, &cert);

      if (status == noErr) {
         CFStringRef cert_summary = _mongoc_ssl_apple_copy_cert_subject (cert);
         char cert_summary_c[128];

         if (cert_summary) {
            memset (cert_summary_c, 0, sizeof(cert_summary_c));

            if (CFStringGetCString (cert_summary,
                                    cert_summary_c,
                                    sizeof(cert_summary_c),
                                    kCFStringEncodingUTF8)) {
               MONGOC_INFO ("Loaded client identity: %s.", cert_summary_c);
            }

            CFRelease (cert_summary);
            CFRelease (cert);
         }

         certs_c[0] = cert_and_key;
         certs = CFArrayCreate (NULL, (const void **)certs_c, 1L,
                                &kCFTypeArrayCallBacks);
         status = SSLSetCertificate (ssl, certs);
      }

      if (certs) {
         CFRelease (certs);
      }

      if (status != noErr) {
         MONGOC_WARNING ("SSLSetCertificate() failed: OSStatus %d.", status);
         return false;
      }

      CFRelease (cert_and_key);

      return true;
   }

   return false;
}

char *
_mongoc_ssl_apple_extract_subject (const char *filename)
{
   MONGOC_WARNING ("x509 subject extraction isn't implemented for"
                   " native apple TLS.");
   return NULL;
}

SSLContextRef
_mongoc_ssl_apple_new (mongoc_ssl_opt_t   *opt,
                       bool                is_client)
{
   SSLContextRef out;

   if (is_client) {
      out = SSLCreateContext (NULL, kSSLClientSide, kSSLStreamType);
   } else {
      out = SSLCreateContext (NULL, kSSLServerSide, kSSLStreamType);
   }

   if (opt->native_identity) {
      if (!_mongoc_ssl_apple_load_identity (out, opt->native_identity)) {
         CFRelease (out);

         return NULL;
      }
   }

   return out;
}

void
_mongoc_ssl_apple_destroy (SSLContextRef ssl)
{
   CFRelease (ssl);
}

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_apple_init --
 *
 *       No-op.
 *
 *-------------------------------------------------------------------------
 */

void
_mongoc_ssl_apple_init (void)
{
   /* no-op */
}

/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_apple_cleanup --
 *
 *       No-op.
 *
 *-------------------------------------------------------------------------
 */

void
_mongoc_ssl_apple_cleanup (void)
{
   /* no-op */
}


#endif /* MONGOC_APPLE_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
