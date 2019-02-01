#include "signverifier.h"

#include <botan-2/botan/pubkey.h>
#include <botan-2/botan/p11_rsa.h>
#include <botan-2/botan/pubkey.h>
#include <botan-2/botan/secmem.h>
#include <botan-2/botan/b64_filt.h>
#include <botan-2/botan/pipe.h>

#include <boost/optional.hpp>

namespace pkcs11 {

SignVerifier::SignVerifier(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password) :
  session_(Session::create(pkcs11Module, password, 1))
{

}

void SignVerifier::sign(boost::filesystem::path input, boost::filesystem::path output)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PrivateKey> privKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PrivateKey>(KeyType::PRIVATE, KeyPurpose::SIGNATURE);
  if(privKey)
  {
    Botan::PK_Signer signer(privKey.get(), rng_, "Raw", Botan::IEEE_1363);

    boost::filesystem::ifstream ifstream{input};
    std::string s;
    ifstream >> s;
    Botan::secure_vector<uint8_t> plaintext{s.begin(), s.end()};

    std::vector<uint8_t> signature = signer.sign_message(plaintext, rng_);

    Botan::Pipe pipeOut;
    pipeOut.process_msg(signature);

    boost::filesystem::ofstream ofstream{output};
    ofstream << pipeOut.read_all_as_string();
  }
}

bool SignVerifier::verify(boost::filesystem::path input, boost::filesystem::path signatureFile)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PublicKey> pubKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PublicKey>(KeyType::PUBLIC, KeyPurpose::SIGNATURE);
  if(pubKey)
  {
    boost::filesystem::ifstream ifstream{input};
    std::string t;
    ifstream >> t;
    Botan::secure_vector<uint8_t> plaintext{t.begin(), t.end()};

    boost::filesystem::ifstream ifstreamSig{signatureFile};
    std::string s;
    ifstreamSig >> s;
    Botan::secure_vector<uint8_t> signature{s.begin(), s.end()};

    Botan::PK_Verifier verifier(pubKey.get(), "Raw", Botan::IEEE_1363);
    return verifier.verify_message(plaintext, signature);
  }
  return false;
}

} // namespace pkcs11
