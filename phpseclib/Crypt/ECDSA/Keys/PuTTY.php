<?php

/**
 * PuTTY Formatted ECDSA Key Handler
 *
 * PHP version 5
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
use phpseclib\Crypt\Common\Keys\PuTTY as Progenitor;
use phpseclib\Crypt\ECDSA\BaseCurves\Base as BaseCurve;
use phpseclib\Math\Common\FiniteField\Integer;
use phpseclib\Crypt\ECDSA\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;

/**
 * PuTTY Formatted ECDSA Key Handler
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PuTTY extends Progenitor
{
    use Common;

    /**
     * Public Handler
     *
     * @var string
     * @access private
     */
    const PUBLIC_HANDLER = 'phpseclib\Crypt\ECDSA\Keys\OpenSSH';

    /**
     * Supported Key Types
     *
     * @var array
     * @access private
     */
    protected static $types = [
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
        $components = parent::load($key, $password);
        if (!isset($components['private'])) {
            return $components;
        }

        $private = $components['private'];

        $temp = Base64::encode(Strings::packSSH2('s', $components['type']) . $components['public']);
        $components = OpenSSH::load($components['type'] . ' ' . $temp . ' ' . $components['comment']);

        if ($components['curve'] instanceof TwistedEdwardsCurve) {
            if (Strings::shift($private, 4) != "\0\0\0\x20") {
                throw new \RuntimeException('Length of ssh-ed25519 key should be 32');
            }
            $components['dA'] = $components['curve']->extractSecret($private);
        } else {
            list($temp) = Strings::unpackSSH2('i', $private);
            $components['dA'] = $components['curve']->convertInteger($temp);
        }

        return $components;
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\Common\FiniteField\Integer $privateKey
     * @param \phpseclib\Crypt\ECDSA\BaseCurves\Base $curve
     * @param \phpseclib\Math\Common\FiniteField\Integer[] $publicKey
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(Integer $privateKey, BaseCurve $curve, array $publicKey, $password = false)
    {
        self::initialize_static_variables();

        $public = explode(' ', OpenSSH::savePublicKey($curve, $publicKey));
        $name = $public[0];
        $public = Base64::decode($public[1]);
        list(, $length) = unpack('N', Strings::shift($public, 4));
        Strings::shift($public, $length);

        // PuTTY pads private keys with a null byte per the following:
        // https://github.com/github/putty/blob/a3d14d77f566a41fc61dfdc5c2e0e384c9e6ae8b/sshecc.c#L1926
        if (!$curve instanceof TwistedEdwardsCurve) {
            $private = $privateKey->toBytes();
            if (!(strlen($privateKey->toBits()) & 7)) {
                $private ="\0$private";
            }
        }

        $private = $curve instanceof TwistedEdwardsCurve ?
            Strings::packSSH2('s', $privateKey->secret) :
            Strings::packSSH2('s', $private);

        return self::wrapPrivateKey($public, $private, $name, $password);
    }

    /**
     * Convert an ECDSA public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Crypt\ECDSA\BaseCurves\Base $curve
     * @param \phpseclib\Math\Common\FiniteField[] $publicKey
     * @return string
     */
    public static function savePublicKey(BaseCurve $curve, array $publicKey)
    {
        $public = explode(' ', OpenSSH::savePublicKey($curve, $publicKey));
        $type = $public[0];
        $public = Base64::decode($public[1]);
        list(, $length) = unpack('N', Strings::shift($public, 4));
        Strings::shift($public, $length);

        return self::wrapPublicKey($public, $type);
    }
}
