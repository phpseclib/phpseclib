# Post-Quantum support
- adds the functionality to handle FALCON, SPHINCS+ and Dilithium5 operations
- currently, only Dilithium5 was tested in https://github.com/Muzosh/Post-Quantum-Authentication-On-The-Web

**Before usage, call the following function atleast once if you are using OIDs from [here](https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md#oids)**
```php
ASN1::loadOIDs([
    "dilithium2" => "1.3.6.1.4.1.2.267.7.4.4",
    "p256_dilithium2" => "1.3.9999.2.7.1",
    "rsa3072_dilithium2" => "1.3.9999.2.7.2",
    "dilithium3" => "1.3.6.1.4.1.2.267.7.6.5",
    "p384_dilithium3" => "1.3.9999.2.7.3",
    "dilithium5" => "1.3.6.1.4.1.2.267.7.8.7",
    "p521_dilithium5" => "1.3.9999.2.7.4",
    "dilithium2_aes" => "1.3.6.1.4.1.2.267.11.4.4",
    "p256_dilithium2_aes" => "1.3.9999.2.11.1",
    "rsa3072_dilithium2_aes" => "1.3.9999.2.11.2",
    "dilithium3_aes" => "1.3.6.1.4.1.2.267.11.6.5",
    "p384_dilithium3_aes" => "1.3.9999.2.11.3",
    "dilithium5_aes" => "1.3.6.1.4.1.2.267.11.8.7",
    "p521_dilithium5_aes" => "1.3.9999.2.11.4",
    "falcon512" => "1.3.9999.3.1",
    "p256_falcon512" => "1.3.9999.3.2",
    "rsa3072_falcon512" => "1.3.9999.3.3",
    "falcon1024" => "1.3.9999.3.4",
    "p521_falcon1024" => "1.3.9999.3.5",
    "sphincsharaka128frobust" => "1.3.9999.6.1.1",
    "p256_sphincsharaka128frobust" => "1.3.9999.6.1.2",
    "rsa3072_sphincsharaka128frobust" => "1.3.9999.6.1.3",
    "sphincsharaka128fsimple" => "1.3.9999.6.1.4",
    "p256_sphincsharaka128fsimple" => "1.3.9999.6.1.5",
    "rsa3072_sphincsharaka128fsimple" => "1.3.9999.6.1.6",
    "sphincsharaka128srobust" => "1.3.9999.6.1.7",
    "p256_sphincsharaka128srobust" => "1.3.9999.6.1.8",
    "rsa3072_sphincsharaka128srobust" => "1.3.9999.6.1.9",
    "sphincsharaka128ssimple" => "1.3.9999.6.1.10",
    "p256_sphincsharaka128ssimple" => "1.3.9999.6.1.11",
    "rsa3072_sphincsharaka128ssimple" => "1.3.9999.6.1.12",
    "sphincsharaka192frobust" => "1.3.9999.6.2.1",
    "p384_sphincsharaka192frobust" => "1.3.9999.6.2.2",
    "sphincsharaka192fsimple" => "1.3.9999.6.2.3",
    "p384_sphincsharaka192fsimple" => "1.3.9999.6.2.4",
    "sphincsharaka192srobust" => "1.3.9999.6.2.5",
    "p384_sphincsharaka192srobust" => "1.3.9999.6.2.6",
    "sphincsharaka192ssimple" => "1.3.9999.6.2.7",
    "p384_sphincsharaka192ssimple" => "1.3.9999.6.2.8",
    "sphincsharaka256frobust" => "1.3.9999.6.3.1",
    "p521_sphincsharaka256frobust" => "1.3.9999.6.3.2",
    "sphincsharaka256fsimple" => "1.3.9999.6.3.3",
    "p521_sphincsharaka256fsimple" => "1.3.9999.6.3.4",
    "sphincsharaka256srobust" => "1.3.9999.6.3.5",
    "p521_sphincsharaka256srobust" => "1.3.9999.6.3.6",
    "sphincsharaka256ssimple" => "1.3.9999.6.3.7",
    "p521_sphincsharaka256ssimple" => "1.3.9999.6.3.8",
    "sphincssha256128frobust" => "1.3.9999.6.4.1",
    "p256_sphincssha256128frobust" => "1.3.9999.6.4.2",
    "rsa3072_sphincssha256128frobust" => "1.3.9999.6.4.3",
    "sphincssha256128fsimple" => "1.3.9999.6.4.4",
    "p256_sphincssha256128fsimple" => "1.3.9999.6.4.5",
    "rsa3072_sphincssha256128fsimple" => "1.3.9999.6.4.6",
    "sphincssha256128srobust" => "1.3.9999.6.4.7",
    "p256_sphincssha256128srobust" => "1.3.9999.6.4.8",
    "rsa3072_sphincssha256128srobust" => "1.3.9999.6.4.9",
    "sphincssha256128ssimple" => "1.3.9999.6.4.10",
    "p256_sphincssha256128ssimple" => "1.3.9999.6.4.11",
    "rsa3072_sphincssha256128ssimple" => "1.3.9999.6.4.12",
    "sphincssha256192frobust" => "1.3.9999.6.5.1",
    "p384_sphincssha256192frobust" => "1.3.9999.6.5.2",
    "sphincssha256192fsimple" => "1.3.9999.6.5.3",
    "p384_sphincssha256192fsimple" => "1.3.9999.6.5.4",
    "sphincssha256192srobust" => "1.3.9999.6.5.5",
    "p384_sphincssha256192srobust" => "1.3.9999.6.5.6",
    "sphincssha256192ssimple" => "1.3.9999.6.5.7",
    "p384_sphincssha256192ssimple" => "1.3.9999.6.5.8",
    "sphincssha256256frobust" => "1.3.9999.6.6.1",
    "p521_sphincssha256256frobust" => "1.3.9999.6.6.2",
    "sphincssha256256fsimple" => "1.3.9999.6.6.3",
    "p521_sphincssha256256fsimple" => "1.3.9999.6.6.4",
    "sphincssha256256srobust" => "1.3.9999.6.6.5",
    "p521_sphincssha256256srobust" => "1.3.9999.6.6.6",
    "sphincssha256256ssimple" => "1.3.9999.6.6.7",
    "p521_sphincssha256256ssimple" => "1.3.9999.6.6.8",
    "sphincsshake256128frobust" => "1.3.9999.6.7.1",
    "p256_sphincsshake256128frobust" => "1.3.9999.6.7.2",
    "rsa3072_sphincsshake256128frobust" => "1.3.9999.6.7.3",
    "sphincsshake256128fsimple" => "1.3.9999.6.7.4",
    "p256_sphincsshake256128fsimple" => "1.3.9999.6.7.5",
    "rsa3072_sphincsshake256128fsimple" => "1.3.9999.6.7.6",
    "sphincsshake256128srobust" => "1.3.9999.6.7.7",
    "p256_sphincsshake256128srobust" => "1.3.9999.6.7.8",
    "rsa3072_sphincsshake256128srobust" => "1.3.9999.6.7.9",
    "sphincsshake256128ssimple" => "1.3.9999.6.7.10",
    "p256_sphincsshake256128ssimple" => "1.3.9999.6.7.11",
    "rsa3072_sphincsshake256128ssimple" => "1.3.9999.6.7.12",
    "sphincsshake256192frobust" => "1.3.9999.6.8.1",
    "p384_sphincsshake256192frobust" => "1.3.9999.6.8.2",
    "sphincsshake256192fsimple" => "1.3.9999.6.8.3",
    "p384_sphincsshake256192fsimple" => "1.3.9999.6.8.4",
    "sphincsshake256192srobust" => "1.3.9999.6.8.5",
    "p384_sphincsshake256192srobust" => "1.3.9999.6.8.6",
    "sphincsshake256192ssimple" => "1.3.9999.6.8.7",
    "p384_sphincsshake256192ssimple" => "1.3.9999.6.8.8",
    "sphincsshake256256frobust" => "1.3.9999.6.9.1",
    "p521_sphincsshake256256frobust" => "1.3.9999.6.9.2",
    "sphincsshake256256fsimple" => "1.3.9999.6.9.3",
    "p521_sphincsshake256256fsimple" => "1.3.9999.6.9.4",
    "sphincsshake256256srobust" => "1.3.9999.6.9.5",
    "p521_sphincsshake256256srobust" => "1.3.9999.6.9.6",
    "sphincsshake256256ssimple" => "1.3.9999.6.9.7",
    "p521_sphincsshake256256ssimple" => "1.3.9999.6.9.8",
]);
```

# phpseclib - PHP Secure Communications Library

[![CI Status](https://github.com/phpseclib/phpseclib/actions/workflows/ci.yml/badge.svg?branch=master&event=push "CI Status")](https://github.com/phpseclib/phpseclib/actions/workflows/ci.yml?query=branch%3Amaster)

## Supporting phpseclib

- [Become a backer or sponsor on Patreon](https://www.patreon.com/phpseclib)
- [One-time donation via PayPal or crypto-currencies](http://sourceforge.net/donate/index.php?group_id=198487)
- [Subscribe to Tidelift](https://tidelift.com/subscription/pkg/packagist-phpseclib-phpseclib?utm_source=packagist-phpseclib-phpseclib&utm_medium=referral&utm_campaign=readme)

## Introduction

MIT-licensed pure-PHP implementations of the following:

SSH-2, SFTP, X.509, an arbitrary-precision integer arithmetic library, Ed25519 / Ed449 / Curve25519 / Curve449, ECDSA / ECDH (with support for 66 curves), RSA (PKCS#1 v2.2 compliant), DSA / DH, DES / 3DES / RC4 / Rijndael / AES / Blowfish / Twofish / Salsa20 / ChaCha20, GCM / Poly1305

* [Browse Git](https://github.com/phpseclib/phpseclib)

## Documentation

* [Documentation / Manual](https://phpseclib.com/)
* [API Documentation](https://api.phpseclib.com/master/) (generated by Doctum)

## Branches

### master

* Development Branch
* Unstable API
* Do not use in production

### 3.0

* Long term support (LTS) release
* Major expansion of cryptographic primitives
* Minimum PHP version: 5.6.1
* PSR-4 autoloading with namespace rooted at `\phpseclib3`
* Install via Composer: `composer require phpseclib/phpseclib:~3.0`

### 2.0

* Long term support (LTS) release
* Modernized version of 1.0
* Minimum PHP version: 5.3.3
* PSR-4 autoloading with namespace rooted at `\phpseclib`
* Install via Composer: `composer require phpseclib/phpseclib:~2.0`

### 1.0

* Long term support (LTS) release
* PHP4 compatible
* Composer compatible (PSR-0 autoloading)
* Install using Composer: `composer require phpseclib/phpseclib:~1.0`
* Install using PEAR: See [phpseclib PEAR Channel Documentation](http://phpseclib.sourceforge.net/pear.htm)
* [Download 1.0.20 as ZIP](http://sourceforge.net/projects/phpseclib/files/phpseclib1.0.20.zip/download)

## Security contact information

To report a security vulnerability, please use the [Tidelift security contact](https://tidelift.com/security). Tidelift will coordinate the fix and disclosure.

## Support

Need Support?

* [Checkout Questions and Answers on Stack Overflow](http://stackoverflow.com/questions/tagged/phpseclib)
* [Create a Support Ticket on GitHub](https://github.com/phpseclib/phpseclib/issues/new)
* [Browse the Support Forum](http://www.frostjedi.com/phpbb/viewforum.php?f=46) (no longer in use)

## Special Thanks

Special Thanks to our $50+ sponsors!:

- Allan Simon
- [ChargeOver](https://chargeover.com/)

## Contributing

1. Fork the Project

2. Ensure you have Composer installed (see [Composer Download Instructions](https://getcomposer.org/download/))

3. Install Development Dependencies
    ```sh
    composer install
    ```

4. Create a Feature Branch

5. Run continuous integration checks:
   ```sh
   composer run-script all-quality-tools
   ```
   
6. Send us a Pull Request
