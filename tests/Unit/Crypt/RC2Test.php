<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIII Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

require_once 'Crypt/RC2.php';

// this test is just confirming RC2's key expansion
class Unit_Crypt_RC2Test extends PhpseclibTestCase
{
    public function testEncryptPadding()
    {
        $rc2 = new Crypt_RC2(CRYPT_MODE_ECB);

        // unlike Crypt_AES / Crypt_Rijndael, when you tell Crypt_RC2 that the key length is 128-bits the key isn't null padded to that length.
        // instead, RC2 key expansion is used to extend it out to that length. this isn't done for AES / Rijndael since that doesn't define any
        // sort of key expansion algorithm.

        // admittedly, phpseclib is inconsistent in this regard. RC4 and Blowfish support arbitrary key lengths between a certain range, as well,
        // and they don't have any way to set the key length. but then again, neither do those algorithms have their own key expansion algorithm,
        // whereas RC2 does. and technically, AES / Rijndael (and even Twofish) don't support arbitrary key lengths - they support variable key
        // lengths. so in some ways, i suppose this inconsistency somewhat makes sense, although the fact that Crypt_Twofish doesn't have a
        // setKeyLength() function whereas Crypt_AES / Crypt_Rijndael do not is, itself, an inconsistency.

        // but that said, Crypt_RC2 is inconsistent in other ways: if you pass a 128-bit (16-byte) key to it via setKey() the key is not treated
        // as a 128-bit key but rather as a 1024-bit key and is expanded accordingly, not via null padding, but via RC2's key expansion algorithm.

        // this behavior is in contrast to mcrypt, which extends keys via null padding to 1024 bits. it is also in contrast to OpenSSL, which
        // extends keys, via null padding, to 128 bits. mcrypt's approach seems preferable as one can simulate 128 bit keys by using RC2's
        // key expansion algorithm to extend the key to 1024 bits and then changing the first byte of the new key with an inverse pitable mapping.
        // in contrast, to my knowledge, there is no technique for expanding a key less than 128 bits to 128 bits, via RC2 key expansion. the only
        // scenario in that regard is null padding.

        // simple truncation is insufficient, since, quoting RFC2268, "the purpose of the key-expansion algorithm [in RC2] is to modify the key buffer
        // so that each bit of the expanded key depends in a complicated way on every bit of the supplied input key".

        // now, to OpenSSL's credit, null padding is internally consistent with OpenSSL. OpenSSL only supports fixed length keys. For rc2, rc4 and
        // bf (blowfish), all keys are 128 bits (or are null padded / truncated accordingly). to use 40-bit or 64-bit keys with RC4 with OpenSSL you
        // don't use the rc4 algorithm - you use the rc4-40 or rc4-64 algorithm. and similarily, it's not aes-cbc that you use - it's either aes-128-cbc
        // or aes-192-cbc or aes-256-cbc. this is in contrast to mcrypt, which (with the exception of RC2) actually supports variable and arbitrary
        // length keys.

        // superficially, it seens like Rijndael would be another exception to mcrypt's key length handling, but it in fact is not. the reason being that,
        // with mcrypt, when you specify MCRYPT_RIJNDAEL_128 or MCRYPT_RIJNDAEL_192 or MCRYPT_RIJNDAEL_256 the numbers at the end aren't referring to the
        // key length, but rather, the block length. ie. Rijndael, unlike most block ciphers, doesn't just have a variable (but not arbitrary) key length -
        // it also has a variable block length. AES's block length, however, is not variable, so technically, only MCRYPT_RIJNDAEL_128 is AES.

        $rc2->setKey(str_repeat('d', 16), 128);

        $rc2->setPreferredEngine(CRYPT_ENGINE_INTERNAL);
        $internal = $rc2->encrypt('d');

        $result = pack('H*', 'e3b36057f4821346');
        $this->assertEquals($result, $internal, 'Failed asserting that the internal engine produced the correct result');

        $rc2->setPreferredEngine(CRYPT_ENGINE_MCRYPT);
        if ($rc2->getEngine() == CRYPT_ENGINE_MCRYPT) {
            $mcrypt = $rc2->encrypt('d');
            $this->assertEquals($result, $mcrypt, 'Failed asserting that the mcrypt engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize mcrypt engine');
        }

        $rc2->setPreferredEngine(CRYPT_ENGINE_OPENSSL);
        if ($rc2->getEngine() == CRYPT_ENGINE_OPENSSL) {
            $openssl = $rc2->encrypt('d');
            $this->assertEquals($result, $openssl,  'Failed asserting that the OpenSSL engine produced the correct result');
        } else {
            self::markTestSkipped('Unable to initialize OpenSSL engine');
        }
    }
}
