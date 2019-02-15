#include "session.h"

#include <botan/p11_slot.h>
#include <botan/p11_object.h>

#include <algorithm>
#include <vector>
#include <iostream>

namespace pkcs11 {

void Session::showAllSlots(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password)
{
  std::unique_ptr<Botan::PKCS11::Module> module = std::make_unique<Botan::PKCS11::Module>(pkcs11Module.string());
  // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
  //module.reload();

  // only slots with connected token
  std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(*module, true );
  if(slots.empty())
  {
    throw Botan::PKCS11::PKCS11_Error("No slots found.");
  }

  Botan::PKCS11::Info info = module->get_info();
  std::cout << "Library version: " << std::to_string(info.libraryVersion.major) << "." << std::to_string(info.libraryVersion.minor) << '\n';

  for(Botan::PKCS11::SlotId id: slots)
  {
    std::cout << "===========================================================================================================" << '\n';
    try {
      Botan::PKCS11::Slot slot(*module, id);

      Botan::PKCS11::SlotInfo slot_info = slot.get_slot_info();
      std::cout << "Slot id: " << id << '\n';
      std::cout << "Slot firmware version: " << std::to_string( slot_info.firmwareVersion.major ) << "."
                << std::to_string( slot_info.firmwareVersion.minor ) << '\n';
      std::cout << "Slot manufacturerId: " << slot_info.manufacturerID << '\n';
      std::cout << "Slot description: " << slot_info.slotDescription << '\n';

      Botan::PKCS11::TokenInfo token_info = slot.get_token_info();
      std::cout << "Token firmware version: " << std::to_string( token_info.firmwareVersion.major ) << "."
                << std::to_string( token_info.firmwareVersion.minor ) << '\n';
      std::string manufacturerId(reinterpret_cast<char*>(token_info.manufacturerID), sizeof(token_info.manufacturerID));
      std::cout << "Token manufacturerId: " << manufacturerId << '\n';
      std::cout << "Token label: " << std::string(reinterpret_cast<char*>(token_info.label), sizeof(token_info.label)) << '\n';
      std::cout << "Token model: " << std::string(reinterpret_cast<char*>(token_info.model), sizeof(token_info.model)) << '\n';

      // retrieve all mechanisms supported by the token
      std::vector<Botan::PKCS11::MechanismType> mechanisms = slot.get_mechanism_list();
      for(Botan::PKCS11::MechanismType type : mechanisms)
      {
        std::cout << "MechanismType: " << static_cast<int>(type) << '\n';
        Botan::PKCS11::MechanismInfo mech_info =
          slot.get_mechanism_info(type);

        // maximum RSA key length supported:
        std::cout << "Max key lenght: " << mech_info.ulMaxKeySize << '\n';
        std::cout << "Min key lenght: " << mech_info.ulMinKeySize << '\n';
        std::cout << "Flags : " << mech_info.flags << '\n';
      }

      // initialize the token
      //Botan::PKCS11::secure_string so_pin = {};
      //slot.initialize("Botan PKCS11 documentation test label", so_pin );

      Botan::PKCS11::Flags flags =
        Botan::PKCS11::flags( Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession );

      Botan::PKCS11::Session session( slot, flags, nullptr, nullptr );

      session.login( Botan::PKCS11::UserType::User, password);

      {
        Botan::PKCS11::PublicKeyProperties publicKeyProperties(Botan::PKCS11::KeyType::Rsa);
        std::vector<Botan::PKCS11::Attribute> pubAttributes = publicKeyProperties.attributes();
        Botan::PKCS11::ObjectFinder pubFinder(session, pubAttributes);

        std::vector<Botan::PKCS11::ObjectHandle> pubHandles = pubFinder.find();
        pubFinder.finish();

        if(pubHandles.empty())
        {
          std::cout << "Cannot find public key" << '\n';
          return;
        }
        std::cout << "===========================================================================================================" << '\n';
        std::cout << "Found " << pubHandles.size() << " public keys " << '\n';
        std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';

        for(Botan::PKCS11::ObjectHandle pubHandle: pubHandles)
        {
          try
          {
            Botan::PKCS11::PKCS11_RSA_PublicKey pubKey(session, pubHandle);
            Botan::secure_vector<uint8_t> pubKeyLabel = pubKey.get_attribute_value(Botan::PKCS11::AttributeType::Label);
            std::string pubKeyLabelString(reinterpret_cast<char*>(pubKeyLabel.data()), pubKeyLabel.size());
            std::cout << pubKeyLabelString << " (public)\n";
            Botan::secure_vector<uint8_t> pubKeyId = pubKey.get_attribute_value(Botan::PKCS11::AttributeType::Id);
            std::cout << "Public key Id: ";
            for(uint8_t keyid: pubKeyId)
            {
              std::cout << std::to_string(keyid);
            }
            std::cout << '\n';
            std::cout << "Public key Fingerprint: " << pubKey.fingerprint_public() << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
          catch(Botan::PKCS11::PKCS11_ReturnError &e)
          {
            std::cout << "PKCS11_ReturnError: " << e.what() << '\n';
            Botan::PKCS11::ReturnValue value = e.get_return_value();
            std::cout << pkcs11ErrorToStr(value) << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
          catch(Botan::Lookup_Error &e)
          {
            std::cout << "Lookup_Error: " << e.what() << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
        }
      }

      {
        Botan::PKCS11::PrivateKeyProperties privateKeyProperties(Botan::PKCS11::KeyType::Rsa);
        std::vector<Botan::PKCS11::Attribute> attributes = privateKeyProperties.attributes();
        Botan::PKCS11::ObjectFinder finder(session, attributes);
        std::vector<Botan::PKCS11::ObjectHandle> handles = finder.find();
        finder.finish();

        if(handles.empty())
        {
          std::cout << "Cannot find private key" << '\n';
          return;
        }
        std::cout << "===========================================================================================================" << '\n';
        std::cout << "Found " << handles.size() << " private keys\n";
        std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';

        for(Botan::PKCS11::ObjectHandle handle: handles)
        {
          try
          {
            Botan::PKCS11::PKCS11_RSA_PrivateKey privKey(session, handle);
            Botan::secure_vector<uint8_t> l = privKey.get_attribute_value(Botan::PKCS11::AttributeType::Label);
            std::string keyLabel(reinterpret_cast<char*>(l.data()), l.size());
            std::cout << keyLabel << " (private)\n";
            Botan::secure_vector<uint8_t> i = privKey.get_attribute_value(Botan::PKCS11::AttributeType::Id);
            std::cout << "Private key Id: ";
            for(uint8_t keyid: i)
            {
              std::cout << std::to_string(keyid);
            }
            std::cout << '\n';
            std::cout << "Private key Fingerprint: " << privKey.fingerprint_public() << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
          catch(Botan::PKCS11::PKCS11_ReturnError &e)
          {
            std::cout << "PKCS11_ReturnError: " << e.what() << '\n';
            Botan::PKCS11::ReturnValue value = e.get_return_value();
            std::cout << pkcs11ErrorToStr(value) << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
          catch(Botan::Lookup_Error &e)
          {
            std::cout << "Lookup_Error: " << e.what() << '\n';
            std::cout << "-----------------------------------------------------------------------------------------------------------" << '\n';
          }
        }
      }
    }
    catch(Botan::PKCS11::PKCS11_ReturnError &e)
    {
      std::cout << "PKCS11_ReturnError: " << e.what() << '\n';
      Botan::PKCS11::ReturnValue value = e.get_return_value();
      std::cout << pkcs11ErrorToStr(value) << '\n';
    }
    catch(Botan::Lookup_Error &e)
    {
      std::cout << "Lookup_Error: " << e.what() << '\n';
    }
  }
}


std::unique_ptr<Session> Session::create(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id)
{
    std::unique_ptr<Botan::PKCS11::Module> module = std::make_unique<Botan::PKCS11::Module>(pkcs11Module.string());
    // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
    //module.reload();

    // only slots with connected token
    std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(*module, true );
    if(slots.empty())
    {
        throw Botan::PKCS11::PKCS11_Error("No slots found.");
    }

    Botan::PKCS11::Slot slot(*module, id);

    return std::make_unique<Session>(std::move(module), std::move(slot), password);
}

Session::Session(std::unique_ptr<Botan::PKCS11::Module>&& module, Botan::PKCS11::Slot &&slot, Botan::PKCS11::secure_string password) :
    module_(std::move(module)), slot_(std::move(slot)), session_(slot_, false)//flags, nullptr, nullptr)
{
    session_.login( Botan::PKCS11::UserType::User, password);
}

} // namespace pkcs11
