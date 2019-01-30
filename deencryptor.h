#ifndef DEENCRYPTOR_H
#define DEENCRYPTOR_H

#include "session.h"

#include <botan-2/botan/p11.h>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/secmem.h>

#include <boost/filesystem.hpp>

#include <memory>

namespace pkcs11 {

class DeEncryptor
{
public:
    DeEncryptor(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password);

    void encrypt(boost::filesystem::path input, boost::filesystem::path output);

    void decrypt(boost::filesystem::path input, boost::filesystem::path output);

private:
    std::unique_ptr<Session> session_;
    Botan::AutoSeeded_RNG rng_;
};

} // namespace pkcs11

#endif // DEENCRYPTOR_H
