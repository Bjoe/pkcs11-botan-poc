#include <iostream>
#include <string>
#include <vector>

#include <botan/secmem.h>
#include <botan/p11.h>
#include <botan/p11_module.h>
#include <botan/p11_slot.h>
#include <botan/p11_session.h>
#include <botan/p11_rsa.h>
#include <botan/p11_object.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/pipe.h>
#include <botan/b64_filt.h>

#include <boost/program_options.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include <optional>
//#include <filesystem> <-- should be in C++17

#include "deencryptor.h"
#include "signverifier.h"

class ProgramOptions
{
public:
    ProgramOptions(boost::program_options::options_description commandLineOptions) : commandLineOptions_(commandLineOptions)
    {}

    Botan::PKCS11::secure_string getPassword() const
    {
        std::string x = vm_["password"].as<std::string>();
        Botan::PKCS11::secure_string ss(x.begin(), x.end());
        return ss;
    }

    boost::filesystem::path getModule() const
    {
        std::string x = vm_["module"].as<std::string>();
        boost::filesystem::path pt(x);
        return pt;
    }

    bool isListAllSlotsObject() const
    {
        return vm_.count("list");
    }

    bool isEncrypt() const
    {
        return vm_.count("encrypt");
    }

    bool isDecrypt() const
    {
        return vm_.count("decrypt");
    }

    bool isSign() const
    {
        return vm_.count("sign");
    }

    bool isVerify() const
    {
        return vm_.count("verify");
    }

    boost::optional<boost::filesystem::path> getContent() const
    {
        if(vm_.count("input"))
        {
            std::string x = vm_["input"].as<std::string>();
            boost::filesystem::path pt(x);
            return std::move(pt);
        }
        else
        {
            return boost::optional<boost::filesystem::path>{};
        }
    }

    boost::optional<boost::filesystem::path> getOutput() const
    {
        if(vm_.count("output"))
        {
            std::string x = vm_["output"].as<std::string>();
            boost::filesystem::path pt(x);
            return std::move(pt);
        }
        else
        {
            return boost::optional<boost::filesystem::path>{};
        }
    }

    boost::optional<boost::filesystem::path> getSignatureFile() const
    {
        if(vm_.count("signature"))
        {
            std::string x = vm_["signature"].as<std::string>();
            boost::filesystem::path pt(x);
            return std::move(pt);
        }
        else
        {
            return boost::optional<boost::filesystem::path>{};
        }
    }

    void printHelp() const
    {
        std::cout << commandLineOptions_ << '\n';
    }

    static std::optional<ProgramOptions> create(int argc, const char* const argv[], boost::program_options::options_description commandLineOptions)
    {
        ProgramOptions options(commandLineOptions);
        try
        {
            boost::program_options::store(boost::program_options::parse_command_line(argc, argv, commandLineOptions), options.vm_);
            if(options.vm_.count("help"))
            {
                options.printHelp();
                return std::optional<ProgramOptions>{};
            }
            if(!options.vm_.count("module") || !options.vm_.count("password"))
            {
                std::cerr << "The required parameter --module and --password is missing:\n";
                options.printHelp();
                return std::optional<ProgramOptions>{};
            }
            if(!boost::filesystem::exists(options.getModule()))
            {
                std::cerr << "Module " << options.getModule().string() << " doesn't exists\n";
                options.printHelp();
                return std::optional<ProgramOptions>{};
            }
        }
        catch(const boost::program_options::error &ex)
        {
            std::cerr << ex.what() << '\n';
            std::cout << commandLineOptions << '\n';
            return std::optional<ProgramOptions>{};
        }
        return std::move(options);
    }

private:
    boost::program_options::variables_map vm_;
    boost::program_options::options_description commandLineOptions_;
};

std::optional<ProgramOptions> parseCommandLine(int argc, const char* const argv[])
{

    boost::program_options::options_description commandLineOptions{"Options"};
    commandLineOptions.add_options()
            ("help,h", "Help message")
            ("module,m", boost::program_options::value<std::string>(), "Path to pkcs11 module")
            ("password,p", boost::program_options::value<std::string>(), "Password")
            ("list,l", "List Objects and slots")
            ("input,i", boost::program_options::value<std::string>(), "Content to encrypt,decrypt or sign")
            ("output,o", boost::program_options::value<std::string>(), "Encrypt, decrypt or sign output")
            ("decrypt,d", "Decrypt")
            ("encrypt,e", "Encrypt")
            ("sign,s", "Signing")
            ("signature,g", boost::program_options::value<std::string>(), "Signature")
            ("verify,r", "Verify")
            ;

    return ProgramOptions::create(argc, argv, commandLineOptions);
}

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

int main(int argc, const char* const argv[])
{
    std::optional<ProgramOptions> programOptions = parseCommandLine(argc, argv);

    if(programOptions)
    {
        boost::filesystem::path mp = programOptions->getModule();
        std::cout << "Load module from " << mp.string() << '\n';

        if(programOptions->isListAllSlotsObject())
        {
            Botan::PKCS11::Module module(mp.string());
            module.reload();

            // only slots with connected token
            std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots( module, true );

            if(slots.empty())
            {
                std::cout << "No slots" << '\n';
                return 1;
            }
            Botan::PKCS11::Info info = module.get_info();
            std::cout << "Library version: " << std::to_string(info.libraryVersion.major) << "." << std::to_string(info.libraryVersion.minor) << '\n';

            for(Botan::PKCS11::SlotId id: slots)
            {
                std::cout << "===========================================================================================================" << '\n';
                try {
                    Botan::PKCS11::Slot slot(module, id);

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
                    }
                    // retrieve information about a particular mechanism
                    Botan::PKCS11::MechanismInfo mech_info =
                            slot.get_mechanism_info(Botan::PKCS11::MechanismType::RsaPkcs);

                    // maximum RSA key length supported:
                    std::cout << "Max key lenght: " << mech_info.ulMaxKeySize << '\n';

                    // initialize the token
                    //Botan::PKCS11::secure_string so_pin = {};
                    //slot.initialize("Botan PKCS11 documentation test label", so_pin );

                    Botan::PKCS11::Flags flags =
                            Botan::PKCS11::flags( Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession );

                    Botan::PKCS11::Session session( slot, flags, nullptr, nullptr );

                    Botan::PKCS11::secure_string pin = programOptions->getPassword();
                    session.login( Botan::PKCS11::UserType::User, pin );

                    {
                        Botan::PKCS11::PublicKeyProperties publicKeyProperties(Botan::PKCS11::KeyType::Rsa);
                        std::vector<Botan::PKCS11::Attribute> pubAttributes = publicKeyProperties.attributes();
                        Botan::PKCS11::ObjectFinder pubFinder(session, pubAttributes);

                        std::vector<Botan::PKCS11::ObjectHandle> pubHandles = pubFinder.find();
                        pubFinder.finish();

                        if(pubHandles.empty())
                        {
                            std::cout << "Cannot find public key" << '\n';
                            return 1;
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
                            return 1;
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

        if(programOptions->isEncrypt() || programOptions->isDecrypt() ||
                programOptions->isSign() || programOptions->isVerify())
        {

            boost::optional<boost::filesystem::path> contentFile = programOptions->getContent();
            if(contentFile)
            {
                if(boost::filesystem::exists(*contentFile))
                {
                    try {
                        if(programOptions->isEncrypt() || programOptions->isDecrypt())
                        {
                            boost::optional<boost::filesystem::path> output = programOptions->getOutput();
                            if(!output)
                            {
                                std::cerr << "Required --output parameter is missing\n";
                                return -1;
                            }

                            pkcs11::DeEncryptor deencryptor(mp, programOptions->getPassword());

                            if(programOptions->isEncrypt())
                            {
                                deencryptor.encrypt(contentFile.get(), output.get());
                            }

                            if(programOptions->isDecrypt())
                            {
                                deencryptor.decrypt(contentFile.get(), output.get());
                            }
                        }

                        if(programOptions->isSign() || programOptions->isVerify())
                        {
                            pkcs11::SignVerifier verifier(mp, programOptions->getPassword());

                            if(programOptions->isSign())
                            {
                                boost::optional<boost::filesystem::path> output = programOptions->getOutput();
                                if(!output)
                                {
                                    std::cerr << "Required --output parameter is missing\n";
                                    return -1;
                                }

                                verifier.sign(contentFile.get(), output.get());
                            }

                            if(programOptions->isVerify())
                            {
                                boost::optional<boost::filesystem::path> signatureFile = programOptions->getSignatureFile();
                                if(!signatureFile)
                                {
                                    std::cerr << "Required --signature parameter is missing\n";
                                    return -1;
                                }

                                verifier.verify(contentFile.get(), signatureFile.get());
                            }
                        }
                    } catch(Botan::PKCS11::PKCS11_ReturnError &e)
                    {
                        std::cout << "PKCS11_ReturnError: " << e.what() << '\n';
                        Botan::PKCS11::ReturnValue value = e.get_return_value();
                        std::cout << pkcs11ErrorToStr(value) << '\n';
                    }

                }
                else
                {
                    std::cerr << "Content file " << contentFile->string() << " doesn't exists.\n";
                    return -1;
                }
            }
            else
            {
                std::cerr << "Required parameter --file is missing\n";
                programOptions->printHelp();
                return -1;
            }
        }
    }
    return 0;
}

/*
 * Library version: 0.19
===========================================================================================================
Slot id: 0
Slot firmware version: 0.0
Slot manufacturerId: Nitrokey                        
Slot description: Nitrokey Nitrokey Storage (0000000000000) 00 00                 Nitrokey                        
Token firmware version: 3.3
Token manufacturerId: ZeitControl
Token label: User PIN (OpenPGP card)
Token model: PKCS#15 emulated
MechanismType: 1
MechanismType: 0
Max key lenght: 2048
===========================================================================================================
Found 2 public keys
-----------------------------------------------------------------------------------------------------------
Encryption key (public)
Public key Id: 2
Public key Fingerprint: 42:2C:69:8E:9F:C2:1D:39:B9:98:AC:DA:15:E7:BF:44:7E:7E:9C:76:B8:2D:11:1A:9A:73:71:80:A4:52:84:BE
-----------------------------------------------------------------------------------------------------------
Authentication key (public)
Public key Id: 3
Public key Fingerprint: 43:43:DA:6C:73:77:41:F2:A6:B4:D3:ED:2E:EB:9A:00:28:DD:00:5E:69:86:93:37:07:E8:47:E4:D6:05:50:01
-----------------------------------------------------------------------------------------------------------
===========================================================================================================
Found 2 private keys
-----------------------------------------------------------------------------------------------------------
Encryption key (private)
Private key Id: 2
Private key Fingerprint: 42:2C:69:8E:9F:C2:1D:39:B9:98:AC:DA:15:E7:BF:44:7E:7E:9C:76:B8:2D:11:1A:9A:73:71:80:A4:52:84:BE
-----------------------------------------------------------------------------------------------------------
Authentication key (private)
Private key Id: 3
Private key Fingerprint: 43:43:DA:6C:73:77:41:F2:A6:B4:D3:ED:2E:EB:9A:00:28:DD:00:5E:69:86:93:37:07:E8:47:E4:D6:05:50:01
-----------------------------------------------------------------------------------------------------------
===========================================================================================================
Slot id: 1
Slot firmware version: 0.0
Slot manufacturerId: Nitrokey                        
Slot description: Nitrokey Nitrokey Storage (0000000000000) 00 00                 Nitrokey                        
Token firmware version: 3.3
Token manufacturerId: ZeitControl
Token label: User PIN (sig) (OpenPGP card)
Token model: PKCS#15 emulated
MechanismType: 1
MechanismType: 0
Max key lenght: 2048
===========================================================================================================
Found 1 public keys
-----------------------------------------------------------------------------------------------------------
Signature key (public)
Public key Id: 1
Public key Fingerprint: 63:73:97:01:1D:0A:D3:C9:EB:97:19:60:6C:50:BB:26:75:53:C1:3A:FB:FF:B8:B1:08:C4:83:34:37:DE:44:0F
-----------------------------------------------------------------------------------------------------------
===========================================================================================================
Found 1 private keys
-----------------------------------------------------------------------------------------------------------
Signature key (private)
Private key Id: 1
Private key Fingerprint: 63:73:97:01:1D:0A:D3:C9:EB:97:19:60:6C:50:BB:26:75:53:C1:3A:FB:FF:B8:B1:08:C4:83:34:37:DE:44:0F
-----------------------------------------------------------------------------------------------------------
*/
