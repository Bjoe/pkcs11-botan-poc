#include "generatekey.h"

#include <botan/p11_rsa.h>

#include <iostream>

namespace pkcs11 {

GenerateKey::GenerateKey(boost::filesystem::path pkcs11Module, Botan::PKCS11::secure_string password, Botan::PKCS11::SlotId id)
    :
      session_(Session::create(pkcs11Module, password, id)),
      rng_{}
{

}

bool GenerateKey::generate()
{
  Botan::PKCS11::RSA_PrivateKeyGenerationProperties privProps;
  privProps.set_label("Encryption key");
  privProps.set_token(true);
  privProps.set_private(true);
  privProps.set_sign(false);
  privProps.set_decrypt(true);

  Botan::PKCS11::RSA_PublicKeyGenerationProperties pubProps( 2048UL );
  pubProps.set_pub_exponent();
  pubProps.set_label("Encryption key");
  pubProps.set_token(true);
  pubProps.set_encrypt(true);
  pubProps.set_verify(false);
  pubProps.set_private(false);

  session_->doItInsideSession([&](Botan::PKCS11::Session& session)
                              {
                                Botan::PKCS11::PKCS11_RSA_KeyPair rsaKeypair =
                                  Botan::PKCS11::generate_rsa_keypair( session, pubProps, privProps );

                                Botan::PKCS11::PKCS11_RSA_PublicKey pubKey = rsaKeypair.first;
                                std::cout << "Public key fingerprint: " << pubKey.fingerprint_public() << '\n';

                                Botan::PKCS11::PKCS11_RSA_PrivateKey privKey = rsaKeypair.second;
                                std::cout << "Private key fingerprint: " << privKey.fingerprint_public() << '\n';

                              });
  return true;
}

} // namespace pkcs11
