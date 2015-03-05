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

#include <stdio.h>

#include "mongoc-b64-private.h"
#include "mongoc-ssl-apple-private.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/mman.h>
#include <Security/SecureTransport.h>
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>

static int read_cert(const char *file, unsigned char **out, size_t *outlen)
{
    int fd;
    ssize_t n, len = 0, cap = 512;
    unsigned char buf[cap], *data;

    fd = open(file, 0);
    if(fd < 0)
        return -1;

    data = bson_malloc(cap);
    if(!data) {
        close(fd);
        return -1;
    }

    for(;;) {
        n = read(fd, buf, sizeof(buf));
        if(n < 0) {
            close(fd);
            bson_free(data);
            return -1;
        }
        else if(n == 0) {
            close(fd);
            break;
        }

        if(len + n >= cap) {
            cap *= 2;
            data = bson_realloc(data, cap);
            if(!data) {
                close(fd);
                return -1;
            }
        }

        memcpy(data + len, buf, n);
        len += n;
    }
    data[len] = '\0';

    *out = data;
    *outlen = len;

    return 0;
}


static long pem_to_der(const char *in, unsigned char **out, size_t *outlen)
{
  char *sep_start, *sep_end, *cert_start, *cert_end;
  size_t i, j, err;
  size_t len;
  int rval;
  unsigned char *b64;

  /* Jump through the separators at the beginning of the certificate. */
  sep_start = strstr(in, "-----");
  if(sep_start == NULL)
    return 0;
  cert_start = strstr(sep_start + 1, "-----");
  if(cert_start == NULL)
    return -1;

  cert_start += 5;

  /* Find separator after the end of the certificate. */
  cert_end = strstr(cert_start, "-----");
  if(cert_end == NULL)
    return -1;

  sep_end = strstr(cert_end + 1, "-----");
  if(sep_end == NULL)
    return -1;
  sep_end += 5;

  len = cert_end - cert_start;
  b64 = bson_malloc(len + 1);

  /* Create base64 string without linefeeds. */
  for(i = 0, j = 0; i < len; i++) {
    if(cert_start[i] != '\r' && cert_start[i] != '\n')
      b64[j++] = cert_start[i];
  }
  b64[j] = '\0';

  rval = mongoc_b64_pton((char *)b64, NULL, 0);

  if (rval < 0) {
      return -1;
  }

  *outlen = rval;
  *out = bson_malloc(*outlen);

  mongoc_b64_pton((char *)b64, *out, *outlen);

  bson_free(b64);

  return sep_end - in;
}


static CFStringRef CopyCertSubject(SecCertificateRef cert)
{
  CFStringRef server_cert_summary = CFSTR("(null)");

#if TARGET_OS_IPHONE
  /* iOS: There's only one way to do this. */
  server_cert_summary = SecCertificateCopySubjectSummary(cert);
#else
#if MAC_OS_X_VERSION_MAX_ALLOWED < 1070
  /* Lion & later: Get the long description if we can. */
  if(SecCertificateCopyLongDescription != NULL)
    server_cert_summary =
      SecCertificateCopyLongDescription(NULL, cert, NULL);
  else
#endif /* 10.7 */
#if MAC_OS_X_VERSION_MAX_ALLOWED < 1060
  /* Snow Leopard: Get the certificate summary. */
  if(SecCertificateCopySubjectSummary != NULL)
    server_cert_summary = SecCertificateCopySubjectSummary(cert);
  else
#endif /* 10.6 */
  /* Leopard is as far back as we go... */
  (void)SecCertificateCopyCommonName(cert, &server_cert_summary);
#endif
  return server_cert_summary;
}
static bool append_cert_to_array(unsigned char *buf, size_t buflen,
                                CFMutableArrayRef array)
{
    char subject_cbuf[128];
    CFDataRef certdata = CFDataCreate(kCFAllocatorDefault, buf, buflen);

    if(!certdata) {
//      failf(data, "SSL: failed to allocate array for CA certificate");
      return false;
    }

    SecCertificateRef cacert =
      SecCertificateCreateWithData(kCFAllocatorDefault, certdata);
    CFRelease(certdata);
    if(!cacert) {
 //     failf(data, "SSL: failed to create SecCertificate from CA certificate");
      return false;
    }

    /* Check if cacert is valid. */
    CFStringRef subject = CopyCertSubject(cacert);
    if(subject) {
      memset(subject_cbuf, 0, 128);
      if(!CFStringGetCString(subject,
                            subject_cbuf,
                            128,
                            kCFStringEncodingUTF8)) {
        CFRelease(cacert);
//        failf(data, "SSL: invalid CA certificate subject");
          return false;
      }
      CFRelease(subject);
    }
    else {
      CFRelease(cacert);
//      failf(data, "SSL: invalid CA certificate");
      return false;
    }

    CFArrayAppendValue(array, cacert);
    CFRelease(cacert);

    return true;
}


bool _mongoc_ssl_apple_load_pkcs12(mongoc_ssl_apple_t *ssl, const char *cPath, const char *cPassword)
{
      fprintf(stderr, "cpath: %s, cpassword: %s\n", cPath, cPassword);
  
  OSStatus status = errSecItemNotFound;
  CFURLRef pkcs_url = CFURLCreateFromFileSystemRepresentation(NULL,
    (const UInt8 *)cPath, strlen(cPath), false);
  CFStringRef password = cPassword ? CFStringCreateWithCString(NULL,
    cPassword, kCFStringEncodingUTF8) : NULL;
  CFDataRef pkcs_data = NULL;
      fprintf(stderr, "got to %d\n", __LINE__);

  /* We can import P12 files on iOS or OS X 10.7 or later: */
  /* These constants are documented as having first appeared in 10.6 but they
     raise linker errors when used on that cat for some reason. */
#if 1
  if(CFURLCreateDataAndPropertiesFromResource(NULL, pkcs_url, &pkcs_data,
    NULL, NULL, &status)) {
      fprintf(stderr, "got to %d\n", __LINE__);
    const void *cKeys[] = {kSecImportExportPassphrase};
    const void *cValues[] = {password};
    CFDictionaryRef options = CFDictionaryCreate(NULL, cKeys, cValues,
      password ? 1L : 0L, NULL, NULL);
    CFArrayRef items = NULL;

    /* Here we go: */
    status = SecPKCS12Import(pkcs_data, options, &items);
      fprintf(stderr, "got to %d\n", __LINE__);
    if(status == noErr && items && CFArrayGetCount(items)) {
      fprintf(stderr, "got to %d\n", __LINE__);
      CFDictionaryRef identity_and_trust = CFArrayGetValueAtIndex(items, 0L);
      const void *temp_identity = CFDictionaryGetValue(identity_and_trust,
        kSecImportItemIdentity);

      /* Retain the identity; we don't care about any other data... */
      CFRetain(temp_identity);
      ssl->cert_and_key = (SecIdentityRef)temp_identity;
    }

    if(items)
      CFRelease(items);
    CFRelease(options);
    CFRelease(pkcs_data);
  }
#endif /* CURL_BUILD_MAC_10_7 || CURL_BUILD_IOS */
      fprintf(stderr, "got to %d\n", __LINE__);
  if(password)
    CFRelease(password);
  CFRelease(pkcs_url);
      fprintf(stderr, "got to %d\n", __LINE__);

  fprintf(stderr, "status: %d\n", status);
  if (status == noErr) {
      SecCertificateRef cert = NULL;
      CFTypeRef certs_c[1];
      CFArrayRef certs;

      /* If we found one, print it out: */
      status = SecIdentityCopyCertificate(ssl->cert_and_key, &cert);
      fprintf(stderr, "got to %d\n", __LINE__);
      if(status == noErr) {
      fprintf(stderr, "got to %d\n", __LINE__);
        CFStringRef cert_summary = CopyCertSubject(cert);
        char cert_summary_c[128];

        if(cert_summary) {
          memset(cert_summary_c, 0, 128);
          if(CFStringGetCString(cert_summary,
                                cert_summary_c,
                                128,
                                kCFStringEncodingUTF8)) {
//            infof(data, "Client certificate: %s\n", cert_summary_c);
          }
          CFRelease(cert_summary);
          CFRelease(cert);
        }
      }
      if(certs)
        CFRelease(certs);
      if(status != noErr) {
//        failf(data, "SSL: SSLSetCertificate() failed: OSStatus %d", err);
        return false;
      }
      CFRelease(ssl->cert_and_key);

      fprintf(stderr, "got to %d\n", __LINE__);
      return true;
  } else {
      fprintf(stderr, "got to %d\n", __LINE__);
      return false;
  }
}


static bool
_mongoc_ssl_apple_load_cert (mongoc_ssl_apple_t *ssl, const char *cafile)
{
    int n = 0;
    bool rc;
    long res;
    unsigned char *certbuf, *der;
    size_t buflen, derlen, offset = 0;

    BSON_ASSERT (ssl);
    BSON_ASSERT (cafile);

    if(read_cert(cafile, &certbuf, &buflen) < 0) {
//        failf(data, "SSL: failed to read or invalid CA certificate");
        return false;
    }

    CFMutableArrayRef array = ssl->anchor_certs;

    while(offset < buflen) {
        n++;

        /*
         * Check if the certificate is in PEM format, and convert it to DER. If
         * this fails, we assume the certificate is in DER format.
         */
        res = pem_to_der((const char *)certbuf + offset, &der, &derlen);
        if(res < 0) {
            bson_free(certbuf);
//            failf(data, "SSL: invalid CA certificate #%d (offset %d) in bundle",
 //                   n, offset);
            return false;
        }
        offset += res;

        if(res == 0) {
            /* No more certificates in the bundle. */
            bson_free(certbuf);
            break;
        }

        rc = append_cert_to_array(der, derlen, array);
        free(der);
        if(! rc) {
            bson_free(certbuf);
            return rc;
        }
    }

    return true;
}


/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_ssl_apple_extract_subject --
 *
 *       Extract human-readable subject information from the certificate
 *       in @filename.
 *
 *       Depending on the OS version, we try several different ways of
 *       accessing this data, and the string returned may be a summary
 *       of the certificate, a long description of the certificate, or
 *       just the common name from the cert.
 *
 * Returns:
 *       Certificate data, or NULL if filename could not be processed.
 *
 *-------------------------------------------------------------------------
 */

char *
_mongoc_ssl_apple_extract_subject (const char *filename)
{
    return NULL;
}

void
_mongoc_ssl_apple_new (mongoc_ssl_opt_t *opt, mongoc_ssl_apple_t *out, bool is_client)
{
   memset(out, 0, sizeof (*out));

   out->anchor_certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);

   if (is_client) {
       out->context = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    } else {
       out->context = SSLCreateContext(NULL, kSSLServerSide, kSSLStreamType);
    }
//   SSLSetSessionOption(out->context, kSSLSessionOptionBreakOnClientAuth, true);
//   SSLSetSessionOption(out->context, kSSLSessionOptionBreakOnServerAuth, true);
   SSLSetEnableCertVerify(out->context, ! opt->weak_cert_validation);

   if (opt->pkcs12_file) {
       if (opt->pkcs12_pwd) {
           _mongoc_ssl_apple_load_pkcs12(out, opt->pkcs12_file, opt->pkcs12_pwd);
       } else {
           _mongoc_ssl_apple_load_pkcs12(out, opt->pkcs12_file, "");
       }
   }

   if (opt->ca_file) {
       _mongoc_ssl_apple_load_cert (out, opt->ca_file);
    }
}

void
_mongoc_ssl_apple_destroy (mongoc_ssl_apple_t *out)
{
   CFRelease(out->context);
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
   // TODO why is this a no-op?
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
   // TODO why is this a no-op?
}


#endif /* MONGOC_APPLE_NATIVE_TLS */
#endif /* MONGOC_ENABLE_SSL */
