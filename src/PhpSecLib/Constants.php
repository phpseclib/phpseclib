<?php

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_MODE_CTR', -1);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_MODE_ECB', 1);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_MODE_CBC', 2);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_MODE_CFB', 3);

/**
 * Encrypt / decrypt using the Output Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_MODE_OFB', 4);

/**
 * Encrypt / decrypt using streaming mode.
 *
 */
define('CRYPT_MODE_STREAM', 5);

/**
 * Base value for the internal implementation $engine switch
 */
define('CRYPT_MODE_INTERNAL', 1);

/**
 * Base value for the mcrypt implementation $engine switch
 */
define('CRYPT_MODE_MCRYPT', 2);

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_AES_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_AES_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_AES_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_AES_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_AES_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_AES_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_AES_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_BLOWFISH_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_BLOWFISH_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_BLOWFISH_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_BLOWFISH_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_BLOWFISH_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_BLOWFISH_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_BLOWFISH_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Contains $keys[CRYPT_DES_ENCRYPT]
 */
define('CRYPT_DES_ENCRYPT', 0);

/**
 * Contains $keys[CRYPT_DES_DECRYPT]
 */
define('CRYPT_DES_DECRYPT', 1);

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_DES_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_DES_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_DES_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_DES_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_DES_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_DES_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_DES_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Toggles the internal implementation
 */
define('CRYPT_HASH_MODE_INTERNAL', 1);

/**
 * Toggles the mhash() implementation, which has been deprecated on PHP 5.3.0+.
 */
define('CRYPT_HASH_MODE_MHASH',    2);

/**
 * Toggles the hash() implementation, which works on PHP 5.1.2+.
 */
define('CRYPT_HASH_MODE_HASH',     3);

/**
 * "Is Windows" test
 */
define('CRYPT_RANDOM_IS_WINDOWS', strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_RC2_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_RC2_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_RC2_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_RC2_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_RC2_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_RC2_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_RC2_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Toggles the internal implementation
 */
define('CRYPT_RC4_MODE_INTERNAL', CRYPT_MODE_INTERNAL);
/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_RC4_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

define('CRYPT_RC4_ENCRYPT', 0);
define('CRYPT_RC4_DECRYPT', 1);

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_RIJNDAEL_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_RIJNDAEL_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_RIJNDAEL_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_RIJNDAEL_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_RIJNDAEL_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_RIJNDAEL_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_RIJNDAEL_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
 * (OAEP) for encryption / decryption.
 *
 * Uses sha1 by default.
 *
 * @see Crypt\RSA::setHash()
 * @see Crypt\RSA::setMGFHash()
 */
define('CRYPT_RSA_ENCRYPTION_OAEP',  1);

/**
 * Use PKCS#1 padding.
 *
 * Although CRYPT_RSA_ENCRYPTION_OAEP offers more security, including PKCS#1 padding is necessary for purposes of backwards
 * compatability with protocols (like SSH-1) written before OAEP's introduction.
 */
define('CRYPT_RSA_ENCRYPTION_PKCS1', 2);

/**
 * Use the Probabilistic Signature Scheme for signing
 *
 * Uses sha1 by default.
 *
 * @see Crypt\RSA::setSaltLength()
 * @see Crypt\RSA::setMGFHash()
 */
define('CRYPT_RSA_SIGNATURE_PSS',  1);

/**
 * Use the PKCS#1 scheme by default.
 *
 * Although CRYPT_RSA_SIGNATURE_PSS offers more security, including PKCS#1 signing is necessary for purposes of backwards
 * compatability with protocols (like SSH-2) written before PSS's introduction.
 */
define('CRYPT_RSA_SIGNATURE_PKCS1', 2);

/**
 * ASN1 Integer
 */
define('CRYPT_RSA_ASN1_INTEGER',   2);

/**
 * ASN1 Bit String
 */
define('CRYPT_RSA_ASN1_BITSTRING', 3); 

/**
 * ASN1 Sequence (with the constucted bit set)
 */
define('CRYPT_RSA_ASN1_SEQUENCE', 48);

/**
 * To use the pure-PHP implementation
 */
define('CRYPT_RSA_MODE_INTERNAL', 1);

/**
 * To use the OpenSSL library
 *
 * (if enabled; otherwise, the internal implementation will be used)
 */
define('CRYPT_RSA_MODE_OPENSSL', 2);

/**
 * Default openSSL configuration file.
 */
define('CRYPT_RSA_OPENSSL_CONFIG', dirname(__FILE__) . '/../openssl.cnf');


/**
 * PKCS#1 formatted protected key
 *
 * Used by OpenSSH
 */
define('CRYPT_RSA_PRIVATE_FORMAT_PKCS1', 0);

/**
 * PuTTY formatted protected key
 */
define('CRYPT_RSA_PRIVATE_FORMAT_PUTTY', 1);

/**
 * XML formatted protected key
 */
define('CRYPT_RSA_PRIVATE_FORMAT_XML', 2);

/**
 * Raw public key
 *
 * An array containing two Math\BigInteger objects.
 *
 * The exponent can be indexed with any of the following:
 *
 * 0, e, exponent, publicExponent
 *
 * The modulus can be indexed with any of the following:
 *
 * 1, n, modulo, modulus
 */
define('CRYPT_RSA_PUBLIC_FORMAT_RAW', 3);

/**
 * PKCS#1 formatted public key (raw)
 *
 * Used by File/X509.php
 */
define('CRYPT_RSA_PUBLIC_FORMAT_PKCS1_RAW', 4);

/**
 * XML formatted public key
 */
define('CRYPT_RSA_PUBLIC_FORMAT_XML', 5);

/**
 * OpenSSH formatted public key
 *
 * Place in $HOME/.ssh/authorized_keys
 */
define('CRYPT_RSA_PUBLIC_FORMAT_OPENSSH', 6);

/**
 * PKCS#1 formatted public key (encapsulated)
 *
 * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
 */
define('CRYPT_RSA_PUBLIC_FORMAT_PKCS1', 7);

/**
 * Encrypt / decrypt using inner chaining
 *
 * Inner chaining is used by SSH-1 and is generally considered to be less secure then outer chaining (CRYPT_DES_MODE_CBC3).
 */
define('CRYPT_DES_MODE_3CBC', -2);

/**
 * Encrypt / decrypt using outer chaining
 *
 * Outer chaining is used by SSH-2 and when the mode is set to CRYPT_DES_MODE_CBC.
 */
define('CRYPT_DES_MODE_CBC3', CRYPT_DES_MODE_CBC);

/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_TWOFISH_MODE_CTR', CRYPT_MODE_CTR);

/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_TWOFISH_MODE_ECB', CRYPT_MODE_ECB);

/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_TWOFISH_MODE_CBC', CRYPT_MODE_CBC);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_TWOFISH_MODE_CFB', CRYPT_MODE_CFB);

/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_TWOFISH_MODE_OFB', CRYPT_MODE_OFB);

/**
 * Toggles the internal implementation
 */
define('CRYPT_TWOFISH_MODE_INTERNAL', CRYPT_MODE_INTERNAL);

/**
 * Toggles the mcrypt implementation
 */
define('CRYPT_TWOFISH_MODE_MCRYPT', CRYPT_MODE_MCRYPT);

/**
 * Tag Classes
 *
 * @access private
 * @link http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#page=12
 */
define('FILE_ASN1_CLASS_UNIVERSAL',        0);
define('FILE_ASN1_CLASS_APPLICATION',      1);
define('FILE_ASN1_CLASS_CONTEXT_SPECIFIC', 2);
define('FILE_ASN1_CLASS_PRIVATE',          3);

/**
 * Tag Classes
 *
 * @access private
 * @link http://www.obj-sys.com/asn1tutorial/node124.html
 */
define('FILE_ASN1_TYPE_BOOLEAN',           1);
define('FILE_ASN1_TYPE_INTEGER',           2);
define('FILE_ASN1_TYPE_BIT_STRING',        3);
define('FILE_ASN1_TYPE_OCTET_STRING',      4);
define('FILE_ASN1_TYPE_NULL',              5);
define('FILE_ASN1_TYPE_OBJECT_IDENTIFIER', 6);
//define('FILE_ASN1_TYPE_OBJECT_DESCRIPTOR', 7);
//define('FILE_ASN1_TYPE_INSTANCE_OF',       8); // EXTERNAL
define('FILE_ASN1_TYPE_REAL',              9);
define('FILE_ASN1_TYPE_ENUMERATED',       10);
//define('FILE_ASN1_TYPE_EMBEDDED',         11);
define('FILE_ASN1_TYPE_UTF8_STRING',      12);
//define('FILE_ASN1_TYPE_RELATIVE_OID',     13);
define('FILE_ASN1_TYPE_SEQUENCE',         16); // SEQUENCE OF
define('FILE_ASN1_TYPE_SET',              17); // SET OF

/**
 * More Tag Classes
 *
 * @access private
 * @link http://www.obj-sys.com/asn1tutorial/node10.html
 */
define('FILE_ASN1_TYPE_NUMERIC_STRING',   18);
define('FILE_ASN1_TYPE_PRINTABLE_STRING', 19);
define('FILE_ASN1_TYPE_TELETEX_STRING',   20); // T61String
define('FILE_ASN1_TYPE_VIDEOTEX_STRING',  21);
define('FILE_ASN1_TYPE_IA5_STRING',       22);
define('FILE_ASN1_TYPE_UTC_TIME',         23);
define('FILE_ASN1_TYPE_GENERALIZED_TIME', 24);
define('FILE_ASN1_TYPE_GRAPHIC_STRING',   25);
define('FILE_ASN1_TYPE_VISIBLE_STRING',   26); // ISO646String
define('FILE_ASN1_TYPE_GENERAL_STRING',   27);
define('FILE_ASN1_TYPE_UNIVERSAL_STRING', 28);
//define('FILE_ASN1_TYPE_CHARACTER_STRING', 29);
define('FILE_ASN1_TYPE_BMP_STRING',       30);

/**
 * Tag Aliases
 *
 * These tags are kinda place holders for other tags.
 *
 * @access private
 */
define('FILE_ASN1_TYPE_CHOICE',          -1);
define('FILE_ASN1_TYPE_ANY',             -2);

/**
 * Flag to only accept signatures signed by certificate authorities
 *
 * Not really used anymore but retained all the same to suppress E_NOTICEs from old installs
 *
 * @access public
 */
define('FILE_X509_VALIDATE_SIGNATURE_BY_CA', 1);

/**
 * Return internal array representation
 */
define('FILE_X509_DN_ARRAY', 0);

/**
 * Return string
 */
define('FILE_X509_DN_STRING', 1);

/**
 * Return ASN.1 name string
 */
define('FILE_X509_DN_ASN1', 2);

/**
 * Return OpenSSL compatible array
 */
define('FILE_X509_DN_OPENSSL', 3);

/**
 * Return canonical ASN.1 RDNs string
 */
define('FILE_X509_DN_CANON', 4);

/**
 * Return name hash for file indexing
 */
define('FILE_X509_DN_HASH', 5);

/**
 * Save as PEM
 *
 * ie. a base64-encoded PEM with a header and a footer
 */
define('FILE_X509_FORMAT_PEM', 0);

/**
 * Save as DER
 */
define('FILE_X509_FORMAT_DER', 1);

/**
 * Save as a SPKAC
 *
 * Only works on CSRs. Not currently supported.
 */
define('FILE_X509_FORMAT_SPKAC', 2);

/**
 * Attribute value disposition.
 * If disposition is >= 0, this is the index of the target value.
 */
define('FILE_X509_ATTR_ALL', -1); // All attribute values (array).
define('FILE_X509_ATTR_APPEND', -2); // Add a value.
define('FILE_X509_ATTR_REPLACE', -3); // Clear first, then add a value.

/**
 * @see Math\BigInteger::_montgomery()
 * @see Math\BigInteger::_prepMontgomery()
 */
define('MATH_BIGINTEGER_MONTGOMERY', 0);

/**
 * @see Math\BigInteger::_barrett()
 */
define('MATH_BIGINTEGER_BARRETT', 1);

/**
 * @see Math\BigInteger::_mod2()
 */
define('MATH_BIGINTEGER_POWEROF2', 2);

/**
 * @see Math\BigInteger::_remainder()
 */
define('MATH_BIGINTEGER_CLASSIC', 3);

/**
 * @see Math\BigInteger::__clone()
 */
define('MATH_BIGINTEGER_NONE', 4);

/**
 * $result[MATH_BIGINTEGER_VALUE] contains the value.
 */
define('MATH_BIGINTEGER_VALUE', 0);

/**
 * $result[MATH_BIGINTEGER_SIGN] contains the sign.
 */
define('MATH_BIGINTEGER_SIGN', 1);

/**
 * Cache constants
 *
 * $cache[MATH_BIGINTEGER_VARIABLE] tells us whether or not the cached data is still valid.
 */
define('MATH_BIGINTEGER_VARIABLE', 0);

/**
 * $cache[MATH_BIGINTEGER_DATA] contains the cached data.
 */
define('MATH_BIGINTEGER_DATA', 1);

/**
 * To use the pure-PHP implementation
 */
define('MATH_BIGINTEGER_MODE_INTERNAL', 1);

/**
 * To use the BCMath library
 *
 * (if enabled; otherwise, the internal implementation will be used)
 */
define('MATH_BIGINTEGER_MODE_BCMATH', 2);

/**
 * To use the GMP library
 *
 * (if present; otherwise, either the BCMath or the internal implementation will be used)
 */
define('MATH_BIGINTEGER_MODE_GMP', 3);

/**
 * Karatsuba Cutoff
 *
 * At what point do we switch between Karatsuba multiplication and schoolbook long multiplication?
 *
 * @access private
 */
define('MATH_BIGINTEGER_KARATSUBA_CUTOFF', 25);

/**
 * Reads data from a local file.
 */
define('NET_SCP_LOCAL_FILE', 1);

/**
 * Reads data from a string.
 */
define('NET_SCP_STRING',  2);

/**
 * SSH1 is being used.
 */
define('NET_SCP_SSH1', 1);

/**
 * SSH2 is being used.
 */
define('NET_SCP_SSH2',  2);

/**
 * Returns the message numbers
 */
define('NET_SFTP_LOG_SIMPLE',  NET_SSH2_LOG_SIMPLE);

/**
 * Returns the message content
 */
define('NET_SFTP_LOG_COMPLEX', NET_SSH2_LOG_COMPLEX);

/**
 * Outputs the message content in real-time.
 */
define('NET_SFTP_LOG_REALTIME', 3);

/**
 * SFTP channel constant
 *
 * Net\SSH2::exec() uses 0 and Net\SSH2::read() / Net\SSH2::write() use 1.
 *
 * @see Net\SSH2::_send_channel_packet()
 * @see Net\SSH2::_get_channel_packet()
 * @access private
 */
define('NET_SFTP_CHANNEL', 0x100);

/**
 * Reads data from a local file.
 */
define('NET_SFTP_LOCAL_FILE',    1);

/**
 * Reads data from a string.
 */
// this value isn't really used anymore but i'm keeping it reserved for historical reasons
define('NET_SFTP_STRING',        2);

/**
 * Resumes an upload
 */
define('NET_SFTP_RESUME',        4);

/**
 * Append a local file to an already existing remote file
 */
define('NET_SFTP_RESUME_START',  8);

/**
 * No encryption
 *
 * Not supported.
 */
define('NET_SSH1_CIPHER_NONE',       0);

/**
 * IDEA in CFB mode
 *
 * Not supported.
 */
define('NET_SSH1_CIPHER_IDEA',       1);

/**
 * DES in CBC mode
 */
define('NET_SSH1_CIPHER_DES',        2);

/**
 * Triple-DES in CBC mode
 *
 * All implementations are required to support this
 */
define('NET_SSH1_CIPHER_3DES',       3);

/**
 * TRI's Simple Stream encryption CBC
 *
 * Not supported nor is it defined in the official SSH1 specs.  OpenSSH, however, does define it (see cipher.h),
 * although it doesn't use it (see cipher.c)
 */
define('NET_SSH1_CIPHER_BROKEN_TSS', 4);

/**
 * RC4
 *
 * Not supported.
 *
 * @internal According to the SSH1 specs:
 *
 *        "The first 16 bytes of the session key are used as the key for
 *         the server to client direction.  The remaining 16 bytes are used
 *         as the key for the client to server direction.  This gives
 *         independent 128-bit keys for each direction."
 *
 *     This library currently only supports encryption when the same key is being used for both directions.  This is
 *     because there's only one $crypto object.  Two could be added ($encrypt and $decrypt, perhaps).
 */
define('NET_SSH1_CIPHER_RC4',        5);

/**
 * Blowfish
 *
 * Not supported nor is it defined in the official SSH1 specs.  OpenSSH, however, defines it (see cipher.h) and
 * uses it (see cipher.c)
 */
define('NET_SSH1_CIPHER_BLOWFISH',   6);

/**
 * .rhosts or /etc/hosts.equiv
 */
define('NET_SSH1_AUTH_RHOSTS',     1);

/**
 * pure RSA authentication
 */
define('NET_SSH1_AUTH_RSA',        2);

/**
 * password authentication
 *
 * This is the only method that is supported by this library.
 */
define('NET_SSH1_AUTH_PASSWORD',   3);

/**
 * .rhosts with RSA host authentication
 */
define('NET_SSH1_AUTH_RHOSTS_RSA', 4);

/**#@+
 * Terminal Modes
 *
 * @link http://3sp.com/content/developer/maverick-net/docs/Maverick.SSH.PseudoTerminalModesMembers.html
 * @access private
 */
define('NET_SSH1_TTY_OP_END',  0);

/**
 * The Response Type
 *
 * @see Net\SSH1::_get_binary_packet()
 * @access private
 */
define('NET_SSH1_RESPONSE_TYPE', 1);

/**
 * The Response Data
 *
 * @see Net\SSH1::_get_binary_packet()
 * @access private
 */
define('NET_SSH1_RESPONSE_DATA', 2);

/**#@+
 * Execution Bitmap Masks
 *
 * @see Net\SSH1::bitmap
 * @access private
 */
define('NET_SSH1_MASK_CONSTRUCTOR', 0x00000001);
define('NET_SSH1_MASK_LOGIN',       0x00000002);
define('NET_SSH1_MASK_SHELL',       0x00000004);

/**
 * Returns the message numbers
 */
define('NET_SSH1_LOG_SIMPLE',  1);

/**
 * Returns the message content
 */
define('NET_SSH1_LOG_COMPLEX', 2);

/**
 * Outputs the content real-time
 */
define('NET_SSH2_LOG_REALTIME', 3);

/**
 * Dumps the content real-time to a file
 */
define('NET_SSH2_LOG_REALTIME_FILE', 4);

/**
 * Returns when a string matching $expect exactly is found
 */
define('NET_SSH1_READ_SIMPLE',  1);

/**
 * Returns when a string matching the regular expression $expect is found
 */
define('NET_SSH1_READ_REGEX', 2);

/**#@+
 * Execution Bitmap Masks
 *
 * @see Net\SSH2::bitmap
 * @access private
 */
define('NET_SSH2_MASK_CONSTRUCTOR',   0x00000001);
define('NET_SSH2_MASK_LOGIN_REQ',     0x00000002);
define('NET_SSH2_MASK_LOGIN',         0x00000004);
define('NET_SSH2_MASK_SHELL',         0x00000008);
define('NET_SSH2_MASK_WINDOW_ADJUST', 0X00000010);
/**#@-*/

/**#@+
 * Channel constants
 *
 * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
 * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
 * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
 * recepient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
 * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snipet:
 *     The 'recipient channel' is the channel number given in the original
 *     open request, and 'sender channel' is the channel number allocated by
 *     the other side.
 *
 * @see Net\SSH2::_send_channel_packet()
 * @see Net\SSH2::_get_channel_packet()
 * @access private
 */
define('NET_SSH2_CHANNEL_EXEC',      0); // PuTTy uses 0x100
define('NET_SSH2_CHANNEL_SHELL',     1);
define('NET_SSH2_CHANNEL_SUBSYSTEM', 2);
/**#@-*/

/**#@+
 * @access public
 * @see Net\SSH2::getLog()
 */
/**
 * Returns the message numbers
 */
define('NET_SSH2_LOG_SIMPLE',  1);
/**
 * Returns the message content
 */
define('NET_SSH2_LOG_COMPLEX', 2);
/**
 * Outputs the content real-time
 */
define('NET_SSH2_LOG_REALTIME', 3);
/**
 * Dumps the content real-time to a file
 */
define('NET_SSH2_LOG_REALTIME_FILE', 4);
/**#@-*/

/**#@+
 * @access public
 * @see Net\SSH2::read()
 */
/**
 * Returns when a string matching $expect exactly is found
 */
define('NET_SSH2_READ_SIMPLE',  1);
/**
 * Returns when a string matching the regular expression $expect is found
 */
define('NET_SSH2_READ_REGEX', 2);
/**
 * Make sure that the log never gets larger than this
 */
define('NET_SSH2_LOG_MAX_SIZE', 1024 * 1024);
/**#@-*/