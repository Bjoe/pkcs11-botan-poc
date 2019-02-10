#ifndef SESSION_H
#define SESSION_H

#include <botan/p11.h>
#include <botan/p11_module.h>
#include <botan/p11_session.h>
#include <botan/p11_rsa.h>
#include <botan/p11_slot.h>
#include <botan/p11_object.h>

#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include <vector>
#include <memory>

namespace pkcs11 {

enum class KeyType
{
    PUBLIC,
    PRIVATE,
};

enum class KeyPurpose
{
    ENCRYPTION,
    SIGNATURE,
};

class Session
{
public:
  static std::unique_ptr<Session> create(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id);
  Session(std::unique_ptr<Botan::PKCS11::Module> &&module, Botan::PKCS11::Slot&& slot, Botan::PKCS11::Flags flags, Botan::PKCS11::secure_string password);

  Session(const Session&) = delete;
  Session& operator=(const Session& other) = delete;

  template<typename T>
  boost::optional<T> getKey(KeyType type, KeyPurpose purpose)
  {
      std::unique_ptr<Botan::PKCS11::KeyProperties> kp;
      switch(type)
      {
          case(KeyType::PUBLIC):
          {
              Botan::PKCS11::KeyType t = Botan::PKCS11::KeyType::Rsa;
              std::unique_ptr<Botan::PKCS11::KeyProperties> k = std::make_unique<Botan::PKCS11::PublicKeyProperties>(t);
              kp.swap(k);
              break;
          }
          case(KeyType::PRIVATE):
          {
              Botan::PKCS11::KeyType t = Botan::PKCS11::KeyType::Rsa;
              std::unique_ptr<Botan::PKCS11::KeyProperties> k = std::make_unique<Botan::PKCS11::PrivateKeyProperties>(t);
              kp.swap(k);
              break;
          }
      }

      std::string keyPurpose = "undefined";
      switch(purpose)
      {
      case(KeyPurpose::SIGNATURE):
          keyPurpose = "Signature key";
          break;
      case(KeyPurpose::ENCRYPTION):
          keyPurpose = "Encryption key";
          break;
      }
      // search for an public key
      kp->add_string(Botan::PKCS11::AttributeType::Label, keyPurpose);
      //publicKeyProperties.add_numeric(Botan::PKCS11::AttributeType::Id, 2);

      std::vector<Botan::PKCS11::Attribute> a = kp->attributes();
      std::vector<T> foundPublicKey =
              Botan::PKCS11::Object::search<T>(session_, a);

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

private:
  std::unique_ptr<Botan::PKCS11::Module> module_;
  Botan::PKCS11::Slot slot_;
  Botan::PKCS11::Session session_;
};

} // namespace pkcs11

#endif // SESSION_H
