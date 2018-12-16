<?php

/**
 * OpenSSH Formatted ECDSA Key Handler
 *
 * PHP version 5
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @category  Crypt
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\ECDSA\Keys;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\Crypt\Common\Keys\OpenSSH as Progenitor;
use phpseclib\Crypt\ECDSA\BaseCurves\Base as BaseCurve;
use phpseclib\Exception\UnsupportedCurveException;
use phpseclib\Crypt\ECDSA\Curves\Ed25519;
use phpseclib\Math\Common\FiniteField\Integer;
use phpseclib\Crypt\Random;

/**
 * OpenSSH Formatted ECDSA Key Handler
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class OpenSSH extends Progenitor
{
    use Common;

    /**
     * Supported Key Types
     *
     * @var array
     */
    private static $types = [
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'ssh-ed25519'
    ];

    /**
     * Break a public or private key down into its constituent components
     *
     * @access public
     * @param string $key
     * @param string $password optional
     * @return array
     */
    public static function load($key, $password = '')
    {
        /*
           key format is described here:
           https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD

           this is only supported for ECDSA because of Ed25519. ssh-keygen doesn't generate a
           PKCS1/8 formatted private key for Ed25519 - it generates an OpenSSH formatted
           private key. probably because, at the time of this writing, there's not an actual
           IETF RFC describing an Ed25519 format
        */
        if (strpos($key, 'BEGIN OPENSSH PRIVATE KEY') !== false) {
            $key = preg_replace('#(?:^-.*?-[\r\n]*$)|\s#ms', '', $key);
            $key = Base64::decode($key);
            $magic = Strings::shift($key, 15);
            if ($magic != "openssh-key-v1\0") {
                throw new \RuntimeException('Expected openssh-key-v1');
            }
            list($ciphername, $kdfname, $kdfoptions, $numKeys) = Strings::unpackSSH2('sssN', $key);
            if ($numKeys != 1) {
                throw new \RuntimeException('Although the OpenSSH private key format supports multiple keys phpseclib does not');
            }
            if (strlen($kdfoptions) || $kdfname != 'none' || $ciphername != 'none') {
                /*
                  OpenSSH private keys use a customized version of bcrypt. specifically, instead of encrypting
                  OrpheanBeholderScryDoubt 64 times OpenSSH's bcrypt variant encrypts
                  OxychromaticBlowfishSwatDynamite 64 times. so we can't use crypt().

                  bcrypt is basically Blowfish with an altered key expansion. whereas Blowfish just runs the
                  key through the key expansion bcrypt interleaves the key expansion with the salt and
                  password. this renders openssl / mcrypt unusuable. this forces us to use a pure-PHP implementation
                  of bcrypt. the problem with that is that pure-PHP is too slow to be practically useful.

                  in addition to encrypting a different string 64 times the OpenSSH also performs bcrypt from
                  scratch $rounds times. calling crypt() 64x with bcrypt takes 0.7s. PHP is going to be naturally
                  slower. pure-PHP is 215x slower than OpenSSL for AES and pure-PHP is 43x slower for bcrypt.
                  43 * 0.7 = 30s. no one wants to wait 30s to load a private key.

                  another way to think about this..  according to wikipedia's article on Blowfish,
                  "Each new key requires pre-processing equivalent to encrypting about 4 kilobytes of text".
                  key expansion is done (9+64*2)*160 times. multiply that by 4 and it turns out that Blowfish,
                  OpenSSH style, is the equivalent of encrypting ~80mb of text.

                  more supporting evidence: sodium_compat does not implement Argon2 (another password hashing
                  algorithm) because "It's not feasible to polyfill scrypt or Argon2 into PHP and get reasonable
                  performance. Users would feel motivated to select parameters that downgrade security to avoid
                  denial of service (DoS) attacks. The only winning move is not to play"
                    -- https://github.com/paragonie/sodium_compat/blob/master/README.md
                */
                throw new \RuntimeException('Encrypted OpenSSH private keys are not supported');
                //list($salt, $rounds) = Strings::unpackSSH2('sN', $kdfoptions);
            }

            list($publicKey, $paddedKey) = Strings::unpackSSH2('ss', $key);
            list($type, $publicKey) = Strings::unpackSSH2('ss', $publicKey);
            if ($type != 'ssh-ed25519') {
                throw new UnsupportedCurveException('ssh-ed25519 is the only supported curve for OpenSSH public keys');
            }
            list($checkint1, $checkint2, $type, $publicKey2, $privateKey, $comment) = Strings::unpackSSH2('NNssss', $paddedKey);
            // any leftover bytes in $paddedKey are for padding? but they should be sequential bytes. eg. 1, 2, 3, etc.
            if ($checkint1 != $checkint2) {
                throw new \RuntimeException('The two checkints do not match');
            }
            if ($type != 'ssh-ed25519') {
                throw new UnsupportedCurveException('ssh-ed25519 is the only supported curve for OpenSSH private keys');
            }
            if ($publicKey != $publicKey2 || $publicKey2 != substr($privateKey, 32)) {
                throw new \RuntimeException('The public keys do not match up');
            }
            $privateKey = substr($privateKey, 0, 32);
            $curve = new Ed25519();
            return [
                'curve' => $curve,
                'dA' => $curve->extractSecret($privateKey),
                'QA' => self::extractPoint($publicKey, $curve),
                'comment' => $comment
            ];
        }

        $parts = explode(' ', $key, 3);

        if (!isset($parts[1])) {
            $key = Base64::decode($parts[0]);
            $comment = isset($parts[1]) ? $parts[1] : false;
        } else {
            $asciiType = $parts[0];
            if (!in_array($asciiType, self::$types)) {
                throw new \RuntimeException('Keys of type ' . $asciiType . ' are not supported');
            }
            $key = Base64::decode($parts[1]);
            $comment = isset($parts[2]) ? $parts[2] : false;
        }

        list($binaryType) = Strings::unpackSSH2('s', $key);
        if (isset($asciiType) && $asciiType != $binaryType) {
            throw new \RuntimeException('Two different types of keys are claimed: ' . $asciiType . ' and ' . $binaryType);
        } elseif (!isset($asciiType) && !in_array($binaryType, self::$types)) {
            throw new \RuntimeException('Keys of type ' . $binaryType . ' are not supported');
        }

        if ($binaryType == 'ssh-ed25519') {
            if (Strings::shift($key, 4) != "\0\0\0\x20") {
                throw new \RuntimeException('Length of ssh-ed25519 key should be 32');
            }

            $curve = new Ed25519();
            $qa = self::extractPoint($key, $curve);
        } else {
            list($curveName, $publicKey) = Strings::unpackSSH2('ss', $key);
            $curveName = '\phpseclib\Crypt\ECDSA\Curves\\' . $curveName;
            $curve = new $curveName();

            $qa = self::extractPoint("\0" . $publicKey, $curve);
        }

        return [
            'curve' => $curve,
            'QA' => $qa,
            'comment' => $comment
        ];
    }

    /**
     * Convert an ECDSA public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Crypt\ECDSA\BaseCurves\Base $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @return string
     */
    public static function savePublicKey(BaseCurve $curve, array $publicKey)
    {
        if ($curve instanceof Ed25519) {
            $key = Strings::packSSH2('ss', 'ssh-ed25519', $curve->encodePoint($publicKey));
            $key = 'ssh-ed25519 ' . Base64::encode($key) . ' ' . self::$comment;
            return $key;
        }

        self::initialize_static_variables();

        $reflect = new \ReflectionClass($curve);
        $name = $reflect->getShortName();

        $oid = self::$curveOIDs[$name];
        $aliases = array_filter(self::$curveOIDs, function($v) use ($oid) {
            return $v == $oid;
        });
        $aliases = array_keys($aliases);

        for ($i = 0; $i < count($aliases); $i++) {
            if (in_array('ecdsa-sha2-' . $aliases[$i], self::$types)) {
                $alias = $aliases[$i];
                break;
            }
        }

        if (!isset($alias)) {
            throw new UnsupportedCurveException($name . ' is not a curve that the OpenSSH plugin supports');
        }

        $points = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();
        $key = Strings::packSSH2('sss', 'ecdsa-sha2-' . $alias, $alias, $points);

        if (self::$binary) {
            return $key;
        }

        $key = 'ecdsa-sha2-' . $alias . ' ' . Base64::encode($key) . ' ' . self::$comment;

        return $key;
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\Common\FiniteField\Integer $privateKey
     * @param \phpseclib\Crypt\ECDSA\Curves\Ed25519 $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(Integer $privateKey, Ed25519 $curve, array $publicKey, $password = '')
    {
        if (!isset($privateKey->secret)) {
            throw new \RuntimeException('Private Key does not have a secret set');
        }
        if (strlen($privateKey->secret) != 32) {
            throw new \RuntimeException('Private Key secret is not of the correct length');
        }

        list(, $checkint) = unpack('N', Random::string(4));
        $pubKey = $curve->encodePoint($publicKey);

        $publicKey = Strings::packSSH2('ss', 'ssh-ed25519', $pubKey);
        $paddedKey = Strings::packSSH2('NNssss', $checkint, $checkint, 'ssh-ed25519', $pubKey, $privateKey->secret . $pubKey, self::$comment);
        /*
           from http://tools.ietf.org/html/rfc4253#section-6 :

           Note that the length of the concatenation of 'packet_length',
           'padding_length', 'payload', and 'random padding' MUST be a multiple
           of the cipher block size or 8, whichever is larger.
         */
        $paddingLength = (7 * strlen($paddedKey)) % 8;
        for ($i = 1; $i <= $paddingLength; $i++) {
            $paddedKey.= chr($i);
        }
        $key = Strings::packSSH2('sssNss', 'none', 'none', '', 1, $publicKey, $paddedKey);
        $key = "openssh-key-v1\0$key";

        return "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" .
               chunk_split(Base64::encode($key), 70) . 
               "-----END OPENSSH PRIVATE KEY-----";
    }
}
