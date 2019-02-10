#include "session.h"

#include <botan/p11_slot.h>
#include <botan/p11_object.h>

#include <algorithm>
#include <vector>
#include <iostream>

namespace pkcs11 {

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

    Botan::PKCS11::Flags flags =
            Botan::PKCS11::flags( Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession );

    Botan::PKCS11::Slot slot(*module, id);

    std::unique_ptr<Session> s = std::make_unique<Session>(std::move(module), std::move(slot), flags, password);
    return s;
}

Session::Session(std::unique_ptr<Botan::PKCS11::Module>&& module, Botan::PKCS11::Slot &&slot, Botan::PKCS11::Flags flags, Botan::PKCS11::secure_string password) :
    module_(std::move(module)), slot_(std::move(slot)), session_(slot_, false)//flags, nullptr, nullptr)
{
    Botan::PKCS11::SlotId id = slot.slot_id();
    session_.login( Botan::PKCS11::UserType::User, password);
    std::cout << "Id " << id << '\n';
}

} // namespace pkcs11
