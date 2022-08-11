<?php

/**
 * OpenSSH Key Handler
 *
 * PHP version 5
 *
 * Place in $HOME/.ssh/authorized_keys
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Crypt\Common\Formats\Keys;

use ParagonIE\ConstantTime\Base64;
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Random;

/**
 * OpenSSH Formatted RSA Key Handler
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class OpenSSH
{
    /**
     * Default comment
     *
     * @var string
     */
    protected static $comment = 'phpseclib-generated-key';

    /**
     * Binary key flag
     *
     * @var bool
     */
    protected static $binary = false;

    /**
     * Sets the default comment
     */
    public static function setComment(string $comment): void
    {
        self::$comment = str_replace(["\r", "\n"], '', $comment);
    }

    /**
     * Break a public or private key down into its constituent components
     *
     * $type can be either ssh-dss or ssh-rsa
     *
     * @param string|array $key
     */
    public static function load($key, ?string $password = null): array
    {
        if (!Strings::is_stringable($key)) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        // key format is described here:
        // https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD

        if (strpos($key, 'BEGIN OPENSSH PRIVATE KEY') !== false) {
            $key = preg_replace('#(?:^-.*?-[\r\n]*$)|\s#ms', '', $key);
            $key = Base64::decode($key);
            $magic = Strings::shift($key, 15);
            if ($magic != "openssh-key-v1\0") {
                throw new \RuntimeException('Expected openssh-key-v1');
            }
            [$ciphername, $kdfname, $kdfoptions, $numKeys] = Strings::unpackSSH2('sssN', $key);
            if ($numKeys != 1) {
                // if we wanted to support multiple keys we could update PublicKeyLoader to preview what the # of keys
                // would be; it'd then call Common\Keys\OpenSSH.php::load() and get the paddedKey. it'd then pass
                // that to the appropriate key loading parser $numKey times or something
                throw new \RuntimeException('Although the OpenSSH private key format supports multiple keys phpseclib does not');
            }

            switch ($ciphername) {
                case 'none':
                    break;
                case 'aes256-ctr':
                    if ($kdfname != 'bcrypt') {
                        throw new \RuntimeException('Only the bcrypt kdf is supported (' . $kdfname . ' encountered)');
                    }
                    [$salt, $rounds] = Strings::unpackSSH2('sN', $kdfoptions);
                    $crypto = new AES('ctr');
                    //$crypto->setKeyLength(256);
                    //$crypto->disablePadding();
                    $crypto->setPassword($password, 'bcrypt', $salt, $rounds, 32);
                    break;
                default:
                    throw new \RuntimeException('The only supported cipherse are: none, aes256-ctr (' . $ciphername . ' is being used)');
            }

            [$publicKey, $paddedKey] = Strings::unpackSSH2('ss', $key);
            [$type] = Strings::unpackSSH2('s', $publicKey);
            if (isset($crypto)) {
                $paddedKey = $crypto->decrypt($paddedKey);
            }
            [$checkint1, $checkint2] = Strings::unpackSSH2('NN', $paddedKey);
            // any leftover bytes in $paddedKey are for padding? but they should be sequential bytes. eg. 1, 2, 3, etc.
            if ($checkint1 != $checkint2) {
                throw new \RuntimeException('The two checkints do not match');
            }
            self::checkType($type);

            return compact('type', 'publicKey', 'paddedKey');
        }

        $parts = explode(' ', $key, 3);

        if (!isset($parts[1])) {
            $key = base64_decode($parts[0]);
            $comment = false;
        } else {
            $asciiType = $parts[0];
            self::checkType($parts[0]);
            $key = base64_decode($parts[1]);
            $comment = $parts[2] ?? false;
        }
        if ($key === false) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        [$type] = Strings::unpackSSH2('s', $key);
        self::checkType($type);
        if (isset($asciiType) && $asciiType != $type) {
            throw new \RuntimeException('Two different types of keys are claimed: ' . $asciiType . ' and ' . $type);
        }
        if (strlen($key) <= 4) {
            throw new \UnexpectedValueException('Key appears to be malformed');
        }

        $publicKey = $key;

        return compact('type', 'publicKey', 'comment');
    }

    /**
     * Toggle between binary and printable keys
     *
     * Printable keys are what are generated by default. These are the ones that go in
     * $HOME/.ssh/authorized_key.
     */
    public static function setBinaryOutput(bool $enabled): void
    {
        self::$binary = $enabled;
    }

    /**
     * Checks to see if the type is valid
     */
    private static function checkType(string $candidate): void
    {
        if (!in_array($candidate, static::$types)) {
            throw new \RuntimeException("The key type ($candidate) is not equal to: " . implode(',', static::$types));
        }
    }

    /**
     * Wrap a private key appropriately
     *
     * @param string|false $password
     */
    protected static function wrapPrivateKey(string $publicKey, string $privateKey, $password, array $options): string
    {
        [, $checkint] = unpack('N', Random::string(4));

        $comment = $options['comment'] ?? self::$comment;
        $paddedKey = Strings::packSSH2('NN', $checkint, $checkint) .
                     $privateKey .
                     Strings::packSSH2('s', $comment);

        $usesEncryption = !empty($password) && is_string($password);

        /*
           from http://tools.ietf.org/html/rfc4253#section-6 :

           Note that the length of the concatenation of 'packet_length',
           'padding_length', 'payload', and 'random padding' MUST be a multiple
           of the cipher block size or 8, whichever is larger.
         */
        $blockSize = $usesEncryption ? 16 : 8;
        $paddingLength = (($blockSize - 1) * strlen($paddedKey)) % $blockSize;
        for ($i = 1; $i <= $paddingLength; $i++) {
            $paddedKey .= chr($i);
        }
        if (!$usesEncryption) {
            $key = Strings::packSSH2('sssNss', 'none', 'none', '', 1, $publicKey, $paddedKey);
        } else {
            $rounds = $options['rounds'] ?? 16;
            $salt = Random::string(16);
            $kdfoptions = Strings::packSSH2('sN', $salt, $rounds);
            $crypto = new AES('ctr');
            $crypto->setPassword($password, 'bcrypt', $salt, $rounds, 32);
            $paddedKey = $crypto->encrypt($paddedKey);
            $key = Strings::packSSH2('sssNss', 'aes256-ctr', 'bcrypt', $kdfoptions, 1, $publicKey, $paddedKey);
        }
        $key = "openssh-key-v1\0$key";

        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" .
               chunk_split(Base64::encode($key), 70, "\n") .
               "-----END OPENSSH PRIVATE KEY-----\n";
    }
}
