#include "signverifier.h"

#include <botan/pubkey.h>
#include <botan/p11_rsa.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/b64_filt.h>
#include <botan/pipe.h>

#include <boost/optional.hpp>

namespace pkcs11 {

SignVerifier::SignVerifier(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id) :
  session_(Session::create(pkcs11Module, password, id))
{

}

void SignVerifier::sign(boost::filesystem::path input, boost::filesystem::path output)
{
  boost::optional<Botan::PKCS11::PKCS11_RSA_PrivateKey> privKey = session_->getKey<Botan::PKCS11::PKCS11_RSA_PrivateKey>(KeyType::PRIVATE, KeyPurpose::SIGNATURE);
  if(privKey)
  {
    Botan::PK_Signer signer(privKey.get(), rng_, "EMSA3(Raw)", Botan::IEEE_1363); // EMSA3(Raw) -> EMSA-PKCS1-v1_5 -> CKM_RSA_PKCS

    boost::filesystem::ifstream ifstream{input};
    Botan::secure_vector<uint8_t> plaintext{};

    std::istreambuf_iterator<char> iter(ifstream);
    std::copy(iter, std::istreambuf_iterator<char>(), std::back_inserter(plaintext));

    std::vector<uint8_t> signature = signer.sign_message(plaintext, rng_);

    Botan::Pipe pipeOut(new Botan::Base64_Encoder);
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
    // We cannot verify via PKCS11 on the GPG-Smartcard. We should export the public key and import again.
    Botan::BigInt n = pubKey->get_n();
    Botan::BigInt e = pubKey->get_e();
    Botan::RSA_PublicKey pub(n, e);

    boost::filesystem::ifstream ifstream{input};
    Botan::secure_vector<uint8_t> plaintext{};

    std::istreambuf_iterator<char> iter(ifstream);
    std::copy(iter, std::istreambuf_iterator<char>(), std::back_inserter(plaintext));

    boost::filesystem::ifstream ifstreamSig{signatureFile};
    std::string s;
    ifstreamSig >> s;
    Botan::secure_vector<uint8_t> signature{s.begin(), s.end()};
    Botan::Pipe pipeIn(new Botan::Base64_Decoder);
    pipeIn.process_msg(signature);

    Botan::PK_Verifier verifier(pub, "EMSA3(Raw)", Botan::IEEE_1363);
    return verifier.verify_message(plaintext, pipeIn.read_all());
  }
  return false;
}

} // namespace pkcs11
