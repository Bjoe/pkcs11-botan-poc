# pkcs11-botan-poc
POC version for smartcard support with pkcs11 and botan

### Build

This build use [hunter](https://docs.hunter.sh/en/latest) to build and add third party libraries.

To build the project, configure the project with cmake with:

`cmake -Hpkcs11-botan-poc -Bbuild`

To switch off hunter, if all third party dependencies are installed on your host, add following parameter:

`-DHUNTER_ENABLED=OFF`

After that, build the project with:

`cmake --build build`
