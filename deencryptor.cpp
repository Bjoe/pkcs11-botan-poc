#include "deencryptor.h"

#include <botan/p11_rsa.h>
#include <botan/pubkey.h>
#include <botan/b64_filt.h>
#include <botan/pipe.h>
#include <iterator>
#include <algorithm>

#include <iostream> // remove me

namespace pkcs11 {

DeEncryptor::DeEncryptor(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id) :
    session_(Session::create(pkcs11Module, password, id)),
    rng_{}
{
}

void DeEncryptor::encrypt(boost::filesystem::path input, boost::filesystem::path output)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PublicKey> pubKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PublicKey>(KeyType::PUBLIC, KeyPurpose::ENCRYPTION);
  if(pubKey)
  {
    // We cannot encrypt via PKCS11 on the GPG-Smartcard. We should export the public key and import again.
    Botan::BigInt n = pubKey->get_n();
    Botan::BigInt e = pubKey->get_e();
    Botan::RSA_PublicKey pub(n, e);

    Botan::PK_Encryptor_EME encryptor(pub, rng_, "EME-PKCS1-v1_5");

    boost::filesystem::ifstream ifstream{input};
    Botan::secure_vector<uint8_t> plaintext{};

    std::istreambuf_iterator<char> iter(ifstream);
    std::copy(iter, std::istreambuf_iterator<char>(), std::back_inserter(plaintext));

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
    std::vector<uint8_t> ciphertext{s.begin(), s.end()};
    Botan::Pipe pipeIn(new Botan::Base64_Decoder);
    pipeIn.process_msg(ciphertext);

    auto decryptText = decryptor.decrypt(pipeIn.read_all());

    Botan::Pipe pipeOut;
    pipeOut.process_msg(decryptText);

    boost::filesystem::ofstream ofstream{output};
    ofstream << pipeOut.read_all_as_string();
  }
}

} // namespace pkcs11
