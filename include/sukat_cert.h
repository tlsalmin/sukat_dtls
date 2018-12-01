#pragma once

#include <openssl/ssl.h>
#include <stdbool.h>

#include "sukat_log.h"

/** @brief Type of data in certificate data. */
typedef enum sukat_cert_data_type
{
  SUKAT_CERT_CERTIFICATE, //!< end-point certificate.
  SUKAT_CERT_PKEY,        //!< Private key for certificate.
  SUKAT_CERT_CA           //!< Additional CA to use.
} sukat_cert_data_t;

/** @brief Different certificate data types */
struct sukat_cert_data
{
  union
  {
    const char *data; //!< Data itself.
    const char *path; //!< Path to data.
  };
  unsigned int len;            //!< 0 on null-terminated data.
  sukat_cert_data_t type;      //!< Which type of data given.
  int form; /**!< SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1 for certificates,
                  EVP_PKEY_* for private keys */
  bool data_as_path_to_file;   //!< If path to data instead of data.
  bool load_certificate_chain; /**!< If path contains whole chain. Also use
                                     data_as_path_to_file when set. */
  bool rsa_key; //!< If true, key in RSA form.
};

/** @brief Sukat options for SSL/DTLS end-points. */
struct sukat_cert_options
{
  struct sukat_cert_data cert;  //!< Certificate to use.
  struct sukat_cert_data pkey;  //!< Private key to use.
  unsigned int n_ca;            //!< Number of CAs at end of options.
  struct sukat_cert_data *cas; //!< Additional CAs to add.
};

struct sukat_cert_init_options
{
  struct sukat_cert_options *cert;
  const SSL_METHOD *method; //!< SSL method to use.
  void *context;            //!< Context for callbacks.
  pem_password_cb *pass_cb; /**!< If set, used as password callback.
                                  \ref context used as user data. */
};

/** @brief Initialize the SSL library. */
void sukat_ssl_init(void);

/** Clean up the SSL library */
void sukat_ssl_cleanup(void);

/**
 * @brief Initialize a new SSL context.
 *
 * @param opts          Options for context.
 * @param method        SSL method to use.
 *
 * @return == NULL      Failure.
 * @return != NULL      Success.
 */
SSL_CTX *sukat_cert_context_init(struct sukat_cert_init_options *opts);

/**
 * @brief Initialize a new ex_index for cookie exchange.
 *
 * Mandatory for DTLS in verifying a clients end-point.
 *
 * @param cookie_len Length of cookie. I recommend 32.
 *
 * @return == -1        Failure.
 * @return >= 0         Index for cookie exchange ex_index.
 */
int sukat_cert_cookie_index_init(long cookie_len);

/**
 * @brief Tear down the certificate cookie index.
 *
 * @param cookie_idx    Index set up by index init.
 */
void sukat_cert_cookie_index_close(int cookie_idx);
