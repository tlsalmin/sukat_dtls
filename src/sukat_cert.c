#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <assert.h>

#include "sukat_cert.h"
#include "sukat_log_internal.h"

#define LOG_DESCRIPTION "sukat_cert"

static int sukat_cert_cookie_index = -1;
static long sukat_cert_cookie_len = -1;

static int sukat_cert_cookie_gen(SSL *ssl, unsigned char *cookie,
                                 unsigned int *cookie_len)
{
  unsigned char *ex_data_cookie = SSL_get_ex_data(ssl, sukat_cert_cookie_index);

  if (ex_data_cookie)
    {
      if (*cookie_len >= sukat_cert_cookie_len)
        {
          DBG("Copying %ld byte random cookie to %p", sukat_cert_cookie_len,
              cookie);
          memcpy(cookie, ex_data_cookie, sukat_cert_cookie_len);
          *cookie_len = sukat_cert_cookie_len;

          return 1;
        }
      else
        {
          ERR("Couldn't copy %ld bytes of cookie data to buffer of size %u",
              sukat_cert_cookie_len, *cookie_len);
        }
    }
  else
    {
      ERR("Failed to get cookie by idx %d from SSL %p.",
          sukat_cert_cookie_index, ssl);
    }
  return 0;
}

static int sukat_cert_cookie_verify(SSL *ssl, unsigned char *cookie,
                                    unsigned int cookie_len)
{
  unsigned char *ex_data_cookie = SSL_get_ex_data(ssl, sukat_cert_cookie_index);

  if (ex_data_cookie)
    {
      if (cookie_len == sukat_cert_cookie_len)
        {
          int ret = memcmp(cookie, ex_data_cookie, cookie_len);

          if (!ret)
            {
              DBG("Cookie matched with client on SSL %p", ssl);
              return 1;
            }
          else
            {
              unsigned int i;

              ERR("Cookie on client %p didn't match: %d", ssl, ret);

              // Not the prettiest.
              for (i = 0; i < cookie_len; i++)
                {
                  DBG("Byte %u: expected: %hhx, got: %hhx", i,
                      ex_data_cookie[i], cookie[i]);
                }
            }
        }
      else
        {
          ERR("Cookie length %u didn't match expected %ld", cookie_len,
              sukat_cert_cookie_len);
        }
    }
  else
    {
      ERR("Failed to get ex_data with index %d from %p",
          sukat_cert_cookie_index, ssl);
    }
  return 0;
}

static X509 *load_x509_data(const char *data, unsigned int len)
{
  X509 *x509 = NULL;
  BIO* bio;

  bio = BIO_new(BIO_s_mem());
  if (bio)
    {
      int ret = BIO_write(bio, data, len);

      if (ret > 0 && (unsigned int)ret == len)
        {

          x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        }
      BIO_free(bio);
    }
  return x509;
}

static bool load_certificate(struct sukat_cert_options *opts,
                             SSL_CTX *ssl_ctx)
{
  bool ret = false;
  X509 *x509 = NULL;
  char errbuf[BUFSIZ];
  struct sukat_cert_data *cert = &opts->cert;

  if (cert->load_certificate_chain &&
           SSL_CTX_use_certificate_chain_file(ssl_ctx, cert->path))
    {
      ERR("Failed to load certificate chain %s as %s: %s", cert->path,
          (cert->form == SSL_FILETYPE_PEM) ? "pem" : "der",
          ERR_error_string(ERR_get_error(), errbuf));
    }
  else if (!cert->load_certificate_chain && cert->data_as_path_to_file &&
      (SSL_CTX_use_certificate_file(ssl_ctx, cert->path, cert->form) != 1))
    {
      ERR("Failed to load certificate %s as %s: %s", cert->path,
          (cert->form == SSL_FILETYPE_PEM) ? "pem" : "der",
          ERR_error_string(ERR_get_error(), errbuf));
    }
  else if (!cert->data_as_path_to_file && cert->form == SSL_FILETYPE_ASN1 &&
           (SSL_CTX_use_certificate_ASN1(
              ssl_ctx, cert->len, (const unsigned char *)cert->data) != 1))
    {
      ERR("Failed to load ASN1 cert data: %s",
          ERR_error_string(ERR_get_error(), errbuf));
    }
  else if (!cert->data_as_path_to_file && cert->form == SSL_FILETYPE_PEM &&
           (!(x509 = load_x509_data(cert->data, cert->len)) ||
            (SSL_CTX_use_certificate(ssl_ctx, x509) != 1)))
    {
      ERR("Failed to %s: %s", (x509) ? "parse PEM" : "use PEM",
          ERR_error_string(ERR_get_error(), errbuf));
    }
  // Partial success.
  else
    {
      struct sukat_cert_data *key = &opts->pkey;

      if (key->data_as_path_to_file && key->rsa_key &&
          SSL_CTX_use_RSAPrivateKey_file(ssl_ctx, key->path, key->form) != 1)
        {
          ERR("Failed to load RSA pkey file %s: %s",
              key->path, ERR_error_string(ERR_get_error(), errbuf));
        }
      else if (key->data_as_path_to_file && !key->rsa_key &&
          SSL_CTX_use_PrivateKey_file(ssl_ctx, key->path, key->form) != 1)
        {
          ERR("Failed to load pkey file %s: %s",
              key->path, ERR_error_string(ERR_get_error(), errbuf));
        }
      else if (!key->data_as_path_to_file && key->rsa_key &&
               SSL_CTX_use_RSAPrivateKey_ASN1(
                 ssl_ctx, (const unsigned char *)key->data, key->len))
        {
          ERR("Failed to load RSA pkey %s",
              ERR_error_string(ERR_get_error(), errbuf));
        }
      else if (!key->data_as_path_to_file && !key->rsa_key &&
               SSL_CTX_use_PrivateKey_ASN1(key->form, ssl_ctx,
                                           (const unsigned char *)key->data,
                                           key->len) != 1)
        {
          ERR("Failed to load pkey form %d: %s",
              key->form, ERR_error_string(ERR_get_error(), errbuf));
        }
      else
        {
          if (SSL_CTX_check_private_key(ssl_ctx) == 1)
            {
              INF("Initialize ssl_ctx %p with certificate and private key",
                  ssl_ctx);
              return true;
            }
          else
            {
              ERR("Failed to match private key and certificate: %s",
                  ERR_error_string(ERR_get_error(), errbuf));
            }
        }
    }
  if (x509)
    {
      X509_free(x509);
    }
  return ret;
}

bool load_ca_chains_verify_locations(struct sukat_cert_options *opts,
                                     SSL_CTX *ssl_ctx)
{
  struct stat statbuf;
  struct sukat_cert_data *ca = opts->cas;

  if (ca->data_as_path_to_file)
    {
      if (!stat(ca->path, &statbuf))
        {
          char errbuf[BUFSIZ];
          bool is_dir = S_ISREG(statbuf.st_mode);

          if (SSL_CTX_load_verify_locations(ssl_ctx,
                                            (!is_dir) ? ca->path : NULL,
                                            (is_dir) ? ca->path : NULL) == 1)
            {
              return true;
            }
          else
            {
              ERR("Failed to load cas from %s: %s",
                  ca->path, ERR_error_string(ERR_get_error(), errbuf));
            }
        }
      else
        {
          ERR("Failed to stat CA file or dir %s: %s", ca->path,
              strerror(errno));
        }
    }
  else
    {
      ERR("Chains set, but not data as path");
    }
  return false;
}

bool load_ca_chain_separate(struct sukat_cert_options *opts,
                            SSL_CTX *ssl_ctx)
{
  //TODO
  (void)opts;
  (void)ssl_ctx;
  return false;
}

bool load_cas(struct sukat_cert_options *opts, SSL_CTX *ssl_ctx)
{
  bool bret = true;

  if (opts->n_ca)
    {
      if (opts->n_ca == 1 &&
          opts->cas[0].load_certificate_chain)
        {
          bret = load_ca_chains_verify_locations(opts, ssl_ctx);
        }
      else
        {
         bret = load_ca_chain_separate(opts, ssl_ctx);
        }
    }
  return bret;
}

SSL_CTX *sukat_cert_context_init(struct sukat_cert_init_options *opts)
{
  char errbuf[BUFSIZ];
  SSL_CTX *ssl_ctx = NULL;

  if (!opts || ! opts->method)
    {
      return NULL;
    }

  ssl_ctx = SSL_CTX_new(opts->method);
  if (ssl_ctx)
    {
      DBG("Created SSL_CTX %p with method %p", ssl_ctx, opts->method);

      if (opts->pass_cb)
        {
          SSL_CTX_set_default_passwd_cb(ssl_ctx, opts->pass_cb);
          SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, opts->context);
        }
      if (!opts->cert || load_certificate(opts->cert, ssl_ctx))
        {
          // Load some CAs.
          if (!opts->cert || load_cas(opts->cert, ssl_ctx))
            {
              if (opts->method == DTLS_server_method() ||
                  opts->method == DTLSv1_2_server_method())
                {
                  SSL_CTX_set_cookie_generate_cb(ssl_ctx,
                                                 sukat_cert_cookie_gen);
                  SSL_CTX_set_cookie_verify_cb(ssl_ctx,
                                               sukat_cert_cookie_verify);
                }
              return ssl_ctx;
            }
        }
      SSL_CTX_free(ssl_ctx);
    }
  else
    {
      ERR("Failed to create SSL context: %s",
          ERR_error_string(ERR_get_error(), errbuf));
    }

  return NULL;
}

static int sukat_cert_cookie_new(__attribute__((unused)) void *parent,
                                 __attribute__((unused)) void *ptr,
                                 CRYPTO_EX_DATA *ad, int idx, long argl,
                                 __attribute__((unused)) void *argp)
{
  if (idx == sukat_cert_cookie_index)
    {
      void *cookie;

      // I know asserting in a library isn't nice, but there are situations.
      assert(argl > 0);
      cookie = malloc(argl);
      if (cookie)
        {
          char errbuf[BUFSIZ];

          if (CRYPTO_set_ex_data(ad, idx, cookie) == 1)
            {
              if (RAND_bytes(cookie, argl) == 1)
                {
                  DBG("Allocated new cookie %p of len %ld to ad %p", cookie,
                      argl, ad);
                  return 1;
                }
              else
                {
                  ERR("Failed to generate %ld random bytes: %s",
                      argl, ERR_error_string(ERR_get_error(), errbuf));
                }
            }
          else
            {
              ERR("Failed to set %p as ex_data to %p with idx %d: %s",
                  cookie, ad, idx, ERR_error_string(ERR_get_error(), errbuf));
            }
          free(cookie);
        }
      else
        {
          ERR("Failed to allocate %ld bytes for cookie: %s",
              argl, strerror(errno));
        }
    }
  else
    {
      DBG("Cert cookie called with ids %d, when expected %d", idx,
          sukat_cert_cookie_index);
    }
  return 0;
}

// I confess, I'm not sure what to do with from_d.
static int sukat_cert_cookie_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
                                 __attribute__((unused)) void *from_d, int idx,
                                 long argl,
                                 __attribute__((unused)) void *argp)
{
  if (idx == sukat_cert_cookie_index)
    {
      void *cookie_from = CRYPTO_get_ex_data(from, idx);

      if (cookie_from)
        {
          void *cookie_to;

          assert(argl > 0);
          cookie_to = malloc(argl);
          if (cookie_to)
            {
              memcpy(cookie_to, cookie_from, argl);

              if (CRYPTO_set_ex_data(to, idx, cookie_to) == 1)
                {
                  DBG("Copied cookie of length %ld from %p to %p, "
                      "from ex %p to ex %p", argl, cookie_from, cookie_to,
                      from, to);
                  return 1;
                }
              else
                {
                  ERR("Failed to set ex_data %p to idx %d: %s",
                      to, idx, strerror(errno));
                }
              free(cookie_to);
            }
          else
            {
              ERR("Failed to allocate %ld bytes: %s", argl, strerror(errno));
            }
        }
      else
        {
          ERR("Couldn't copy cookie from %p as no ex data with idx %d found",
              from, idx);
        }
    }
  else
    {
      DBG("Cert cookie called with ids %d, when expected %d", idx,
          sukat_cert_cookie_index);
    }
  return 0;
}

static void sukat_cert_cookie_free(__attribute__((unused)) void *parent,
                                   __attribute__((unused)) void *ptr,
                                   CRYPTO_EX_DATA *ad, int idx, long argl,
                                   __attribute__((unused)) void *argp)
{
  if (idx == sukat_cert_cookie_index)
    {
      void *cookie = CRYPTO_get_ex_data(ad, idx);

      if (cookie)
        {
          DBG("Freed ex data %p of len %ld from %p", cookie, argl, ad);
          free(cookie);
          CRYPTO_set_ex_data(ad, idx, NULL);
        }
      else
        {
          DBG("No data to free from %p index %d", ad, idx);
        }
    }
  else
    {
      DBG("Cookie free called for id %d when expected %d", idx,
          sukat_cert_cookie_index);
    }
}

int sukat_cert_cookie_index_init(long cookie_len)
{
  sukat_cert_cookie_index = SSL_get_ex_new_index(cookie_len, NULL,
                                                 sukat_cert_cookie_new,
                                                 sukat_cert_cookie_dup,
                                                 sukat_cert_cookie_free);
  if (sukat_cert_cookie_index >= 0)
    {
      sukat_cert_cookie_len = cookie_len;
    }
  return sukat_cert_cookie_index;
}

void sukat_cert_cookie_index_close(__attribute__((unused)) int cookie_idx)
{
  // TODO dig out the uninitialize func
}

void sukat_ssl_init(void)
{
  SSL_library_init();
}

void sukat_ssl_cleanup(void)
{
  ERR_free_strings();
  EVP_cleanup();
}
