<?php

/**
 * PuTTY Formatted DSA Key Handler
 *
 * puttygen does not generate DSA keys with an N of anything other than 160, however,
 * it can still load them and convert them. PuTTY will load them, too, but SSH servers
 * won't accept them. Since PuTTY formatted keys are primarily used with SSH this makes
 * keys with N > 160 kinda useless, hence this handlers not supporting such keys.
 *
 * PHP version 5
 *
 * @category  Crypt
 * @package   DSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\DSA\Keys;

use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\Crypt\Common\Keys\PuTTY as Progenitor;

/**
 * PuTTY Formatted DSA Key Handler
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PuTTY extends Progenitor
{
    /**
     * Public Handler
     *
     * @var string
     * @access private
     */
    const PUBLIC_HANDLER = 'phpseclib\Crypt\DSA\Keys\OpenSSH';

    /**
     * Algorithm Identifier
     *
     * @var string
     * @access private
     */
    const TYPE = 'ssh-dss';

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
        if ($components === false || !isset($components['private'])) {
            return $components;
        }
        extract($components);
        unset($components['public'], $components['private']);

        $result = Strings::unpackSSH2('iiii', $public);
        if ($result === false) {
            return false;
        }
        list($p, $q, $g, $y) = $result;

        $result = Strings::unpackSSH2('i', $private);
        if ($result === false) {
            return false;
        }
        list($x) = $result;

        return compact('p', 'q', 'g', 'y', 'x', 'comment');
    }

    /**
     * Convert a private key to the appropriate format.
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @param \phpseclib\Math\BigInteger $y
     * @param \phpseclib\Math\BigInteger $x
     * @param array $primes
     * @param array $exponents
     * @param array $coefficients
     * @param string $password optional
     * @return string
     */
    public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '')
    {
        if ($q->getLength() != 160) {
            throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
        }

        $public = Strings::packSSH2('iiii', $p, $q, $g, $y);
        $private = Strings::packSSH2('i', $x);

        return self::wrapPrivateKey($public, $private, $password);
    }

    /**
     * Convert a public key to the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $p
     * @param \phpseclib\Math\BigInteger $q
     * @param \phpseclib\Math\BigInteger $g
     * @param \phpseclib\Math\BigInteger $y
     * @return string
     */
    public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
    {
        if ($q->getLength() != 160) {
            throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
        }

        return self::wrapPublicKey(Strings::packSSH2('iiii', $p, $q, $g, $y));
    }
}
