#ifndef SESSION_H
#define SESSION_H

#include <botan-2/botan/p11.h>
#include <botan-2/botan/p11_module.h>
#include <botan-2/botan/p11_session.h>
#include <botan-2/botan/p11_rsa.h>
#include <botan-2/botan/p11_slot.h>
#include <botan-2/botan/p11_object.h>

#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include <vector>
#include <memory>

namespace pkcs11 {

enum class KeyType
{
    ENCRYPTION,
    SIGNATURE,
};

class Session
{
public:
  static std::unique_ptr<Session> create(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id);

  Session(const Session&) = delete;
  Session& operator=(const Session& other) = delete;

  template<typename T>
  boost::optional<T> getKey(KeyType type)
  {
      std::vector<T> foundPublicKey =
              Botan::PKCS11::Object::search<T>(*session_, getAttributes(type));

      if(foundPublicKey.empty())
      {
          return boost::optional<T>{};
      }

      if(foundPublicKey.size() == 1)
      {
          return foundPublicKey.at(0);
      }
      else
      {
          return boost::optional<T>{};
      }
  };

  Session(std::unique_ptr<Botan::PKCS11::Module> module, std::unique_ptr<Botan::PKCS11::Session> session);

private:
  std::vector<Botan::PKCS11::Attribute> getAttributes(KeyType type);

  std::unique_ptr<Botan::PKCS11::Module> module_;
  std::unique_ptr<Botan::PKCS11::Session> session_;
};

} // namespace pkcs11

#endif // SESSION_H
