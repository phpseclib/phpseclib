<?php

/**
 * SSH2 Signature Handler
 *
 * PHP version 5
 *
 * Handles signatures in the format used by SSH2
 *
 * @category  Crypt
 * @package   Common
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\ECDSA\Signature;

use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;

/**
 * SSH2 Signature Handler
 *
 * @package Common
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class SSH2
{
    /**
     * Loads a signature
     *
     * @access public
     * @param string $sig
     * @return mixed
     */
    public static function load($sig)
    {
        if (!is_string($sig)) {
            return false;
        }

        $result = Strings::unpackSSH2('ss', $sig);
        if ($result === false) {
            return false;
        }
        list($type, $blob) = $result;
        switch ($type) {
            // see https://tools.ietf.org/html/rfc5656#section-3.1.2
            case 'ecdsa-sha2-nistp256':
            case 'ecdsa-sha2-nistp384':
            case 'ecdsa-sha2-nistp521':
                break;
            default:
                return false;
        }

        $length = ceil(substr($type, 16) / 8);

        return [
            'r' => new BigInteger(substr($blob, 0, $length), 256),
            's' => new BigInteger(substr($blob, $length), 256)
        ];
    }

    /**
     * Returns a signature in the appropriate format
     *
     * @access public
     * @param \phpseclib\Math\BigInteger $r
     * @param \phpseclib\Math\BigInteger $s
     * @param string $curve
     * @return string
     */
    public static function save(BigInteger $r, BigInteger $s, $curve)
    {
        switch ($curve) {
            case 'nistp256':
            case 'nistp384':
            case 'nistp521':
                break;
            default:
                return false;
        }

        $length = ceil(substr($curve, 5) / 8);

        return Strings::packSSH2('ss', 'ecdsa-sha2-' . $curve,
            str_pad($r->toBytes(), $length, "\0", STR_PAD_LEFT) .
            str_pad($s->toBytes(), $length, "\0", STR_PAD_LEFT)
        );
    }
}
