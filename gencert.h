#pragma once

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, EVP_PKEY **rootkey, int bits);
int add_ext(X509 *cert, int nid, char *value);
int make_root();
int make_crl(X509_CRL **crl, EVP_PKEY **pkeyp, X509 **x509p);
