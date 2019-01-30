#ifndef SIGNVERIFIER_H
#define SIGNVERIFIER_H

#include "session.h"

#include <botan-2/botan/p11.h>
#include <boost/filesystem.hpp>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/secmem.h>

#include <boost/filesystem.hpp>

#include <memory>

namespace pkcs11 {

class SignVerifier
{
public:
  SignVerifier(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password);

  void sign(boost::filesystem::path input, boost::filesystem::path output);

  bool verify(boost::filesystem::path input, boost::filesystem::path signatureFile);

private:
  std::unique_ptr<Session> session_;
  Botan::AutoSeeded_RNG rng_;
};

} // namespace pkcs11

#endif // SIGNVERIFIER_H
