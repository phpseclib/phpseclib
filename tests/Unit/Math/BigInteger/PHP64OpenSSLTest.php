<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2013 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use \phpseclib3\Math\BigInteger\Engines\PHP64;

class Unit_Math_BigInteger_PHP64OpenSSLTest extends Unit_Math_BigInteger_PHP64Test
{
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        try {
            PHP64::setModExpEngine('OpenSSL');
        } catch (BadConfigurationException $e) {
            self::markTestSkipped('openssl_public_encrypt() function is not available.');
        }
    }
}

class PHP64OpenSSLTest extends Unit_Math_BigInteger_PHP64OpenSSLTest
{
}
