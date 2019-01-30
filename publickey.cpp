#include "publickey.h"

#include <botan/p11_object.h>

namespace pkcs11 {

PublicKey::PublicKey(Botan::PKCS11::PKCS11_RSA_PublicKey key) : key_(key)
{

}

} // namespace pkcs11
