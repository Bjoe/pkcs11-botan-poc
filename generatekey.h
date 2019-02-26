#ifndef GENERATEKEY_H
#define GENERATEKEY_H

#include "session.h"

#include <botan/p11.h>
#include <botan/auto_rng.h>

#include <boost/filesystem.hpp>

#include <memory>

namespace pkcs11 {

class GenerateKey
{
public:
  GenerateKey(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id);

  bool generate();
private:
  std::unique_ptr<Session> session_;
  Botan::AutoSeeded_RNG rng_;
};

} // namespace pkcs11

#endif // GENERATEKEY_H
