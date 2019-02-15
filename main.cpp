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

#include "session.h"
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

    Botan::PKCS11::SlotId getSlotId() const
    {
      Botan::PKCS11::SlotId s = vm_["slot"].as<Botan::PKCS11::SlotId>();
      return s;
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
            if(!options.vm_.count("module") ||
                !options.vm_.count("password") ||
                (!options.vm_.count("slot") && !options.vm_.count("list")))
            {
                std::cerr << "Required parameter are missing:\n";
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
            ("slot,t", boost::program_options::value<Botan::PKCS11::SlotId>(), "Slot id")
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


int main(int argc, const char* const argv[])
{
    std::optional<ProgramOptions> programOptions = parseCommandLine(argc, argv);

    if(programOptions)
    {
        boost::filesystem::path mp = programOptions->getModule();
        std::cout << "Load module from " << mp.string() << '\n';
        try {
            if(programOptions->isListAllSlotsObject())
            {
              pkcs11::Session::showAllSlots(mp, programOptions->getPassword());
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

                                pkcs11::DeEncryptor deencryptor(mp, programOptions->getPassword(), programOptions->getSlotId());

                                if(programOptions->isEncrypt())
                                {
                                    std::cout << "Encrypt " << contentFile->string() << " to " << output->string() << '\n';
                                    deencryptor.encrypt(contentFile.get(), output.get());
                                }

                                if(programOptions->isDecrypt())
                                {
                                   std::cout << "Decrypt " << contentFile->string() << " to " << output->string() << '\n';
                                    deencryptor.decrypt(contentFile.get(), output.get());
                                }
                            }

                            if(programOptions->isSign() || programOptions->isVerify())
                            {
                              pkcs11::SignVerifier verifier(mp, programOptions->getPassword(), programOptions->getSlotId());

                                if(programOptions->isSign())
                                {
                                    boost::optional<boost::filesystem::path> output = programOptions->getOutput();
                                    if(!output)
                                    {
                                        std::cerr << "Required --output parameter is missing\n";
                                        return -1;
                                    }

                                    std::cout << "Sign " << contentFile->string() << " signature output: " << output->string() << '\n';
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

                                    std::cout << "Verify " << contentFile->string() << " with " << signatureFile->string() << '\n';
                                    if(verifier.verify(contentFile.get(), signatureFile.get()))
                                    {
                                      std::cout << "Signature is OK!\n";
                                    }
                                    else
                                    {
                                      std::cout << "Signature is WRONG!\n";
                                    }
                                }
                            }
                        } catch(Botan::PKCS11::PKCS11_ReturnError &e)
                        {
                            std::cout << "PKCS11_ReturnError: " << e.what() << '\n';
                            Botan::PKCS11::ReturnValue value = e.get_return_value();
                            std::cout << pkcs11::pkcs11ErrorToStr(value) << '\n';
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
        catch(Botan::PKCS11::PKCS11_Error &e)
        {
            std::cout << "PKCS11_Error: " << e.what() << '\n';
        }
    }
    return 0;
}
