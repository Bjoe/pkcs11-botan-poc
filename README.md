# pkcs11-botan-poc
POC version for NEOPG smartcard support with pkcs11 and botan

### Build

To build the poc version, configure the project with cmake with:

`cmake -Hpkcs11-botan-poc -Bbuild`

Third party dependencies will be build for you via hunter.

If all third party dependencies are installed on your host add following parameter:

`-DHUNTER_ENABLED=OFF`

After that, build the project with:

`cmake --build build`
