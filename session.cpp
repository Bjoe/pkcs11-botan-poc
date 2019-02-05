#include "session.h"

#include <botan/p11_slot.h>
#include <botan/p11_object.h>

#include <algorithm>
#include <vector>

namespace pkcs11 {

std::unique_ptr<Session> Session::create(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id)
{
    std::unique_ptr<Botan::PKCS11::Module> module = std::make_unique<Botan::PKCS11::Module>(pkcs11Module.string());
    // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
    //module.reload();

    // only slots with connected token
    std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots( *module, true );
    if(slots.empty())
    {
        return {};
    }

    Botan::PKCS11::Flags flags =
            Botan::PKCS11::flags( Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession );

    Botan::PKCS11::Slot slot(*module, id);
    std::unique_ptr<Botan::PKCS11::Session> session = std::make_unique<Botan::PKCS11::Session>( slot, flags, nullptr, nullptr);
    session->login( Botan::PKCS11::UserType::User, password);

    return std::make_unique<Session>(std::move(module), std::move(session));
}

Session::Session(std::unique_ptr<Botan::PKCS11::Module> module, std::unique_ptr<Botan::PKCS11::Session> session) :
    module_(std::move(module)), session_(std::move(session))
{

}

namespace
{
std::vector<Botan::PKCS11::Attribute> getPurpsoeAttribute(KeyPurpose purpose, Botan::PKCS11::KeyProperties keyProperties)
{
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
    keyProperties.add_string(Botan::PKCS11::AttributeType::Label, keyPurpose);
    //publicKeyProperties.add_numeric(Botan::PKCS11::AttributeType::Id, 2);
    return keyProperties.attributes();
}

}

// TODO Refactor to template/constexpr
std::vector<Botan::PKCS11::Attribute> Session::getAttributes(KeyType type, KeyPurpose purpose)
{
    switch(type)
    {
    case(KeyType::PUBLIC):
        return getPurpsoeAttribute(purpose, Botan::PKCS11::PublicKeyProperties(Botan::PKCS11::KeyType::Rsa));
    case(KeyType::PRIVATE):
        return getPurpsoeAttribute(purpose, Botan::PKCS11::PrivateKeyProperties(Botan::PKCS11::KeyType::Rsa));
    }
}

} // namespace pkcs11
