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

static const char * pkcs11ErrorToStr(Botan::PKCS11::ReturnValue value)
{
  CK_ULONG res = static_cast<CK_ULONG>(value);
  switch (res) {
    case CKR_OK:
      return "CKR_OK";
    case CKR_CANCEL:
      return "CKR_CANCEL";
    case CKR_HOST_MEMORY:
      return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID:
      return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR:
      return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED:
      return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD:
      return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT:
      return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS:
      return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK:
      return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY:
      return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE:
      return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID:
      return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID:
      return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID:
      return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE:
      return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR:
      return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY:
      return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED:
      return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID:
      return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
      return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED:
      return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL:
      return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED:
      return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID:
      return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:
      return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:
      return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED:
      return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED:
      return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED:
      return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE:
      return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
      return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE:
      return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE:
      return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID:
      return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID:
      return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:
      return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:
      return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:
      return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT:
      return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID:
      return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE:
      return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED:
      return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED:
      return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED:
      return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT:
      return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID:
      return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
      return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY:
      return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS:
      return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS:
      return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
      return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID:
      return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:
      return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE:
      return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT:
      return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT:
      return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED:
      return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED:
      return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
      return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
      return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
      return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN:
      return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN:
      return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED:
      return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID:
      return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
      return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES:
      return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID:
      return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE:
      return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
      return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE:
      return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
      return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
      return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG:
      return "CKR_RANDOM_NO_RNG";
    case CKR_DOMAIN_PARAMS_INVALID:
      return "CKR_DOMAIN_PARAMS_INVALID";
    case CKR_BUFFER_TOO_SMALL:
      return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID:
      return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE:
      return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE:
      return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED:
      return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
      return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD:
      return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED:
      return "CKR_MUTEX_NOT_LOCKED";
    case CKR_VENDOR_DEFINED:
      return "CKR_VENDOR_DEFINED";
  }
  return "unknown PKCS11 error";
}

class Session
{
public:
  static void showAllSlots(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password);
  static std::unique_ptr<Session> create(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id);
  Session(std::unique_ptr<Botan::PKCS11::Module> &&module, Botan::PKCS11::Slot&& slot, Botan::PKCS11::secure_string password);

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
