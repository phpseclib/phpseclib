<?php

/**
 * PublicKeyLoader
 *
 * Returns a PublicKey or PrivateKey object.
 *
 * @category  Crypt
 * @package   PublicKeyLoader
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib3\Crypt;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;

/**
 * PublicKeyLoader
 *
 * @package Common
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
abstract class PublicKeyLoader
{
    /**
     * Loads a public or private key
     *
     * @return AsymmetricKey
     * @access public
     * @param string|array $key
     * @param string $password optional
     */
    public static function load($key, $password = false)
    {
        try {
            return EC::load($key, $password);
        } catch (NoKeyLoadedException $e) {}

        try {
            return RSA::load($key, $password);
        } catch (NoKeyLoadedException $e) {}

        try {
            return DSA::load($key, $password);
        } catch (NoKeyLoadedException $e) {}

        try {
            $x509 = new X509();
            $x509->loadX509($key);
            $key = $x509->getPublicKey();
            if ($key) {
                return $key;
            }
        } catch (\Exception $e) {}

        throw new NoKeyLoadedException('Unable to read key');
    }
}
