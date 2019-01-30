#ifndef PUBLICKEY_H
#define PUBLICKEY_H

#include <botan-2/botan/p11_rsa.h>

namespace pkcs11
{

class PublicKey
{
public:
    PublicKey(Botan::PKCS11::PKCS11_RSA_PublicKey key);


private:
    Botan::PKCS11::PKCS11_RSA_PublicKey key_;
};

} // namespace pkcs11

#endif // PUBLICKEY_H
