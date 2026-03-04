<?php

/**
 * PKCS12 PBKDF Helper for Symmetric Keys and MACs
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common\Traits;

use phpseclib4\Crypt\AES;
use phpseclib4\Crypt\Common\SymmetricKey;
use phpseclib4\Crypt\DES;
use phpseclib4\Crypt\Random;
use phpseclib4\Crypt\RC2;
use phpseclib4\Crypt\RC4;
use phpseclib4\Crypt\TripleDES;
use phpseclib4\Exception\RuntimeException;
use phpseclib4\Exception\UnsupportedAlgorithmException;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Constructed;
use phpseclib4\File\ASN1\Maps;
use phpseclib4\File\ASN1\Types\OctetString;

/**
 * PKCS12 PBKDF Helper for Symmetric Keys and MACs
 *
 * Used by PKCS8, PFX and CMS
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
trait ASN1AlgorithmIdentifier
{
    /**
     * Default encryption algorithm
     *
     * @var string
     */
    private static $defaultEncryptionAlgorithm = 'id-PBES2';

    /**
     * Default encryption scheme
     *
     * Only used when defaultEncryptionAlgorithm is id-PBES2
     *
     * @var string
     */
    private static $defaultEncryptionScheme = 'aes128-CBC-PAD';

    /**
     * Default PRF
     *
     * Only used when defaultEncryptionAlgorithm is id-PBES2
     *
     * @var string
     */
    private static $defaultPRF = 'id-hmacWithSHA256';

    /**
     * Default Iteration Count
     *
     * @var int
     */
    private static $defaultIterationCount = 2048;

    /**
     * Sets the default encryption algorithm
     */
    public static function setEncryptionAlgorithm(string $algo): void
    {
        self::$defaultEncryptionAlgorithm = $algo;
    }

    /**
     * Sets the default encryption algorithm for PBES2
     */
    public static function setEncryptionScheme(string $algo): void
    {
        self::$defaultEncryptionScheme = $algo;
    }

    /**
     * Sets the iteration count
     */
    public static function setIterationCount(int $count): void
    {
        self::$defaultIterationCount = $count;
    }

    /**
     * Sets the PRF for PBES2
     */
    public static function setPRF(string $algo): void
    {
        self::$defaultPRF = $algo;
    }

    /**
     * Returns a SymmetricKey object based on a PBES1 $algo
     *
     * @return SymmetricKey
     */
    private static function getPBES1EncryptionObject(string $algo): SymmetricKey
    {
        $origAlgo = $algo;
        $algo = preg_match('#^pbeWith(?:MD2|MD5|SHA1|SHA)And(.*?)-CBC$#', $algo, $matches) ?
            $matches[1] :
            substr($algo, 13); // strlen('pbeWithSHAAnd') == 13

        switch ($algo) {
            case 'DES':
                $cipher = new DES('cbc');
                break;
            case 'RC2':
                $cipher = new RC2('cbc');
                $cipher->setKeyLength(64);
                break;
            case '3-KeyTripleDES':
                $cipher = new TripleDES('cbc');
                break;
            case '2-KeyTripleDES':
                $cipher = new TripleDES('cbc');
                $cipher->setKeyLength(128);
                break;
            case '128BitRC2':
                $cipher = new RC2('cbc');
                $cipher->setKeyLength(128);
                break;
            case '40BitRC2':
                $cipher = new RC2('cbc');
                $cipher->setKeyLength(40);
                break;
            case '128BitRC4':
                $cipher = new RC4();
                $cipher->setKeyLength(128);
                break;
            case '40BitRC4':
                $cipher = new RC4();
                $cipher->setKeyLength(40);
                break;
            default:
                throw new UnsupportedAlgorithmException("$origAlgo is not a supported algorithm");
        }

        return $cipher;
    }

    /**
     * Returns a hash based on a PBES1 $algo
     */
    private static function getPBES1Hash(string $algo): string
    {
        if (preg_match('#^pbeWith(MD2|MD5|SHA1|SHA)And.*?-CBC$#', $algo, $matches)) {
            return $matches[1] == 'SHA' ? 'sha1' : $matches[1];
        }

        return 'sha1';
    }

    /**
     * Returns a KDF baesd on a PBES1 $algo
     */
    private static function getPBES1KDF(string $algo): string
    {
        switch ($algo) {
            case 'pbeWithMD2AndDES-CBC':
            case 'pbeWithMD2AndRC2-CBC':
            case 'pbeWithMD5AndDES-CBC':
            case 'pbeWithMD5AndRC2-CBC':
            case 'pbeWithSHA1AndDES-CBC':
            case 'pbeWithSHA1AndRC2-CBC':
                return 'pbkdf1';
        }

        return 'pkcs12';
    }

    /**
     * Returns a SymmetricKey object baesd on a PBES2 $algo
     */
    protected static function getPBES2EncryptionObject(string $algo): SymmetricKey
    {
        switch ($algo) {
            case 'desCBC':
                $cipher = new DES('cbc');
                break;
            case 'des-EDE3-CBC':
                $cipher = new TripleDES('cbc');
                break;
            case 'rc2CBC':
                $cipher = new RC2('cbc');
                // in theory this can be changed
                $cipher->setKeyLength(128);
                break;
            case 'rc5-CBC-PAD':
                throw new UnsupportedAlgorithmException('rc5-CBC-PAD is not supported for PBES2 PKCS#8 keys');
            case 'aes128-CBC-PAD':
            case 'aes192-CBC-PAD':
            case 'aes256-CBC-PAD':
                $cipher = new AES('cbc');
                $cipher->setKeyLength((int) substr($algo, 3, 3));
                break;
            default:
                throw new UnsupportedAlgorithmException("$algo is not supported");
        }

        return $cipher;
    }

    private static function getCryptoObjectFromAlgorithmIdentifier(array|Constructed $data, string $password): SymmetricKey
    {
        $meta = [];
        $algorithm = (string) $data['algorithm'];
        switch ($algorithm) {
            // PBES1
            case 'pbeWithMD2AndDES-CBC':
            case 'pbeWithMD2AndRC2-CBC':
            case 'pbeWithMD5AndDES-CBC':
            case 'pbeWithMD5AndRC2-CBC':
            case 'pbeWithSHA1AndDES-CBC':
            case 'pbeWithSHA1AndRC2-CBC':
            case 'pbeWithSHAAnd3-KeyTripleDES-CBC':
            case 'pbeWithSHAAnd2-KeyTripleDES-CBC':
            case 'pbeWithSHAAnd128BitRC2-CBC':
            case 'pbeWithSHAAnd40BitRC2-CBC':
            case 'pbeWithSHAAnd128BitRC4':
            case 'pbeWithSHAAnd40BitRC4':
                $cipher = self::getPBES1EncryptionObject($algorithm);
                $hash = self::getPBES1Hash($algorithm);
                $kdf = self::getPBES1KDF($algorithm);

                $meta['meta']['algorithm'] = $algorithm;

                try {
                    $temp = ASN1::decodeBER((string) $data['parameters']);
                    extract(ASN1::map($temp, Maps\PBEParameter::MAP)->toArray());
                    $iterationCount = (int) $iterationCount->toString();
                    $cipher->setPassword($password, $kdf, $hash, "$salt", $iterationCount);
                    $cipher->setMetaData('meta', $meta);
                    return $cipher;
                } catch (\Exception $e) {
                    throw new RuntimeException('Unable to decode BER', 0, $e);
                }
            case 'id-PBES2':
                $meta['meta']['algorithm'] = $algorithm;

                try {
                    $temp = ASN1::decodeBER((string) $data['parameters']);
                    $temp = ASN1::map($temp, Maps\PBES2params::MAP)->toArray();
                    extract($temp);

                    $cipher = self::getPBES2EncryptionObject((string) $encryptionScheme['algorithm']);
                    $meta['meta']['cipher'] = $encryptionScheme['algorithm'];

                    $temp = ASN1::decodeBER((string) $data['parameters']);
                    $temp = ASN1::map($temp, Maps\PBES2params::MAP)->toArray();
                    extract($temp);
                } catch (\Exception $e) {
                    throw new RuntimeException('Unable to decode BER', 0, $e);
                }

                if (!$cipher instanceof RC2) {
                    $cipher->setIV((string) $encryptionScheme['parameters']);
                } else {
                    try {
                        $temp = ASN1::decodeBER((string) $encryptionScheme['parameters']);
                        extract(ASN1::map($temp, Maps\RC2CBCParameter::MAP)->toArray());
                    } catch (\Exception $e) {
                        throw new RuntimeException('Unable to decode BER', 0, $e);
                    }
                    $effectiveKeyLength = (int) $rc2ParametersVersion->toString();
                    switch ($effectiveKeyLength) {
                        case 160:
                            $effectiveKeyLength = 40;
                            break;
                        case 120:
                            $effectiveKeyLength = 64;
                            break;
                        case 58:
                            $effectiveKeyLength = 128;
                            break;
                        //default: // should be >= 256
                    }
                    $cipher->setIV((string) $iv);
                    $cipher->setKeyLength($effectiveKeyLength);
                }

                $meta['meta']['keyDerivationFunc'] = $keyDerivationFunc['algorithm'];
                $cipher->setMetaData('meta', $meta);
                self::setupPBKDF2($keyDerivationFunc, $password, $cipher);
                return $cipher;
            case 'id-PBMAC1':
                //$temp = ASN1::decodeBER($data['parameters']);
                //$value = ASN1::map($temp[0], Maps\PBMAC1params::MAP)->toArray();
                // since i can't find any implementation that does PBMAC1 it is unsupported
                throw new UnsupportedAlgorithmException('Only PBES1 and PBES2 PKCS#8 keys are supported.');
            // at this point we'll assume that the key conforms to PublicKeyInfo
        }
    }

    protected static function setupPBKDF2(array|Constructed $keyDerivationFunc, string $password, SymmetricKey $cipher): void
    {
        switch ($keyDerivationFunc['algorithm']) {
            case 'id-PBKDF2':
                $meta = $cipher->hasMetaData('meta') ? $cipher->getMetaData('meta') : [];
                $prf = ['algorithm' => 'id-hmacWithSHA1'];
                try {
                    $temp = ASN1::decodeBER((string) $keyDerivationFunc['parameters']);
                    $params = ASN1::map($temp, Maps\PBKDF2params::MAP)->toArray();
                    extract($params);
                } catch (\Exception $e) {
                    throw new RuntimeException('Unable to decode BER', 0, $e);
                }
                $meta['meta']['prf'] = $prf['algorithm'];
                $hash = str_replace('-', '/', substr((string) $prf['algorithm'], 11));
                $params = [
                    $password,
                    'pbkdf2',
                    $hash,
                    (string) $salt,
                    (int) $iterationCount->toString(),
                ];
                if (isset($keyLength)) {
                    $params[] = (int) $keyLength->toString();
                }
                $cipher->setPassword(...$params);
                $cipher->setMetaData('meta', $meta);
                break;
            default:
                throw new UnsupportedAlgorithmException('Only PBKDF2 is supported for PBES2 PKCS#8 keys');
        }
    }

    private static function getCryptoObjectFromParams(string $password, array $options): SymmetricKey
    {
        $salt = Random::string(8);

        $iterationCount = $options['iterationCount'] ?? self::$defaultIterationCount;
        $encryptionAlgorithm = $options['encryptionAlgorithm'] ?? self::$defaultEncryptionAlgorithm;
        $encryptionScheme = $options['encryptionScheme'] ?? self::$defaultEncryptionScheme;
        $prf = $options['PRF'] ?? self::$defaultPRF;

        if ($encryptionAlgorithm == 'id-PBES2') {
            $crypto = self::getPBES2EncryptionObject($encryptionScheme);
            $hash = str_replace('-', '/', substr($prf, 11));
            $kdf = 'pbkdf2';
            $iv = Random::string($crypto->getBlockLength() >> 3);

            $PBKDF2params = [
                'salt' => $salt,
                'iterationCount' => $iterationCount,
                'prf' => ['algorithm' => $prf, 'parameters' => null],
            ];
            $PBKDF2params = ASN1::encodeDER($PBKDF2params, Maps\PBKDF2params::MAP);

            if (!$crypto instanceof RC2) {
                $params = new OctetString($iv);
            } else {
                $params = [
                    'rc2ParametersVersion' => 58,
                    'iv' => $iv,
                ];
                $params = ASN1::encodeDER($params, Maps\RC2CBCParameter::MAP);
                $params = new ASN1\Element($params);
            }

            $params = [
                'keyDerivationFunc' => [
                    'algorithm' => 'id-PBKDF2',
                    'parameters' => new ASN1\Element($PBKDF2params),
                ],
                'encryptionScheme' => [
                    'algorithm' => $encryptionScheme,
                    'parameters' => $params,
                ],
            ];
            $params = ASN1::encodeDER($params, Maps\PBES2params::MAP);

            $crypto->setIV($iv);
        } else {
            $crypto = self::getPBES1EncryptionObject($encryptionAlgorithm);
            $hash = self::getPBES1Hash($encryptionAlgorithm);
            $kdf = self::getPBES1KDF($encryptionAlgorithm);

            $params = [
                'salt' => $salt,
                'iterationCount' => $iterationCount,
            ];
            $params = ASN1::encodeDER($params, Maps\PBEParameter::MAP);
        }
        $crypto->setMetaData('algorithmIdentifier', [
            'algorithm' => $encryptionAlgorithm,
            'parameters' => new ASN1\Element($params),
        ]);
        $crypto->setPassword($password, $kdf, $hash, $salt, $iterationCount);

        return $crypto;
    }
}