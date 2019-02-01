#include "deencryptor.h"

#include <botan-2/botan/p11_rsa.h>
#include <botan-2/botan/pubkey.h>
#include <botan-2/botan/b64_filt.h>
#include <botan-2/botan/pipe.h>

namespace pkcs11 {

DeEncryptor::DeEncryptor(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password) :
    session_(Session::create(pkcs11Module, password, 0)),
    rng_{}
{

}

void DeEncryptor::encrypt(boost::filesystem::path input, boost::filesystem::path output)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PublicKey> pubKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PublicKey>(KeyType::PUBLIC, KeyPurpose::ENCRYPTION);
  if(pubKey)
  {
    Botan::PK_Encryptor_EME encryptor(pubKey.get(), rng_, "EME-PKCS1-v1_5");

    boost::filesystem::ifstream ifstream{input};
    std::string s;
    ifstream >> s;
    Botan::secure_vector<uint8_t> plaintext{s.begin(), s.end()};

    std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, rng_ );

    Botan::Pipe pipe(new Botan::Base64_Encoder);
    pipe.process_msg(ciphertext);

    boost::filesystem::ofstream ofstream{output};
    ofstream << pipe.read_all_as_string();
  }
}

void DeEncryptor::decrypt(boost::filesystem::path input, boost::filesystem::path output)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PrivateKey> privKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PrivateKey>(KeyType::PRIVATE, KeyPurpose::ENCRYPTION);
  if(privKey)
  {
    Botan::PK_Decryptor_EME decryptor( privKey.get(), rng_, "EME-PKCS1-v1_5");

    boost::filesystem::ifstream ifstream{input};
    std::string s;
    ifstream >> s;
    // TODO Base64 Decode
    std::vector<uint8_t> ciphertext{s.begin(), s.end()};
    auto decryptText = decryptor.decrypt(ciphertext);

    Botan::Pipe pipeOut;
    pipeOut.process_msg(decryptText);

    boost::filesystem::ofstream ofstream{output};
    ofstream << pipeOut.read_all_as_string();
  }
}

} // namespace pkcs11
