<?php

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
 *
 * PHP version 5
 *
 * Used by PHP's openssl_public_encrypt() and openssl's rsautl (when -pubin is set)
 *
 * Processes keys with the following headers:
 *
 * -----BEGIN PUBLIC KEY-----
 *
 * Analogous to ssh-keygen's pkcs8 format (as specified by -m). Although PKCS8
 * is specific to private keys it's basically creating a DER-encoded wrapper
 * for keys. This just extends that same concept to public keys (much like ssh-keygen)
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\RSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Crypt\Common\Keys\PKCS8 as Progenitor;
use phpseclib\File\ASN1;

/**
 * PKCS#8 Formatted RSA-PSS Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PSS extends Progenitor
{
    /**
     * OID Name
     *
     * @var string
     * @access private
     */
    const OID_NAME = 'id-RSASSA-PSS';

    /**
     * OID Value
     *
     * @var string
     * @access private
     */
    const OID_VALUE = '1.2.840.113549.1.1.10';

    /**
     * OIDs loaded
     *
     * @var bool
     * @access private
     */
    private static $oidsLoaded = false;

    /**
     * Child OIDs loaded
     *
     * @var bool
     * @access private
     */
    protected static $childOIDsLoaded = false;

    /**
     * Initialize static variables
     */
    private static function initialize_static_variables()
    {
        if (!self::$oidsLoaded) {
            ASN1::loadOIDs([
                'md2' => '1.2.840.113549.2.2',
                'md4' => '1.2.840.113549.2.4',
                'md5' => '1.2.840.113549.2.5',
                'id-sha1' => '1.3.14.3.2.26',
                'id-sha256' => '2.16.840.1.101.3.4.2.1',
                'id-sha384' => '2.16.840.1.101.3.4.2.2',
                'id-sha512' => '2.16.840.1.101.3.4.2.3',
                'id-sha224' => '2.16.840.1.101.3.4.2.4',
                'id-sha512/224' => '2.16.840.1.101.3.4.2.5',
                'id-sha512/256' => '2.16.840.1.101.3.4.2.6',

                'id-mgf1' => '1.2.840.113549.1.1.8'
            ]);
            self::$oidsLoaded = true;
        }
    }

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
        self::initialize_static_variables();

        if (!is_string($key)) {
            throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
        }

        $components = ['isPublicKey' => strpos($key, 'PUBLIC') !== false];

        $key = parent::load($key, $password);

        $type = isset($key['privateKey']) ? 'private' : 'public';

        $result = $components + PKCS1::load($key[$type . 'Key']);

        $decoded = ASN1::decodeBER($key[$type . 'KeyAlgorithm']['parameters']);
        if ($decoded === false) {
            throw new \UnexpectedValueException('Unable to decode parameters');
        }
        $params = ASN1::asn1map($decoded[0], ASN1\Maps\RSASSA_PSS_params::MAP);
        if (isset($params['maskGenAlgorithm']['parameters'])) {
            $decoded = ASN1::decodeBER($params['maskGenAlgorithm']['parameters']);
            if ($decoded === false) {
                throw new \UnexpectedValueException('Unable to decode parameters');
            }
            $params['maskGenAlgorithm']['parameters'] = ASN1::asn1map($decoded[0], ASN1\Maps\HashAlgorithm::MAP);
        } else {
            $params['maskGenAlgorithm'] = [
                'algorithm' => 'id-mgf1',
                'parameters' => ['algorithm' => 'id-sha1']
            ];
        }

        $result['hash'] = str_replace('id-', '', $params['hashAlgorithm']['algorithm']);
        $result['MGFHash'] = str_replace('id-', '', $params['maskGenAlgorithm']['parameters']['algorithm']);
        $result['saltLength'] = (int) $params['saltLength']->toString();

        if (isset($key['meta'])) {
            $result['meta'] = $key['meta'];
        }

        return $result;
    }
}
