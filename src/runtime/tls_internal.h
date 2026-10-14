#pragma once

#include <openssl/bio.h>
#include <openssl/types.h>

namespace rut {

BIO_METHOD* make_tls_engine_bridge_method();

}  // namespace rut
