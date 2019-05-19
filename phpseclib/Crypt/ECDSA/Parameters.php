<?php

/**
 * ECDSA Parameters
 *
 * @category  Crypt
 * @package   ECDSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt\ECDSA;

use phpseclib\Crypt\ECDSA;

/**
 * ECDSA Parameters
 *
 * @package ECDSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Parameters extends ECDSA
{
    /**
     * Returns the public key
     *
     * @param string $type
     * @return string
     */
    public function toString($type = 'PKCS1')
    {
        $type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

        return $type::saveParameters($this->curve);
    }
}
