<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;

abstract class PhpseclibFunctionalTestCase extends PhpseclibTestCase
{
    public static function setUpBeforeClass()
    {
        if (extension_loaded('runkit')) {
            if (extension_loaded('gmp')) {
                self::ensureConstant(
                    'MATH_BIGINTEGER_MODE',
                    BigInteger::MODE_GMP
                );
            } elseif (extension_loaded('bcmath')) {
                self::ensureConstant(
                    'MATH_BIGINTEGER_MODE',
                    BigInteger::MODE_BCMATH
                );
            } else {
                self::markTestSkipped(
                    'Should have gmp or bcmath extension for functional test.'
                );
            }
            self::reRequireFile('Math/BigInteger.php');
        }
        parent::setUpBeforeClass();
    }

    /**
     * @param string $variable
     * @param string|null $message
     *
     * @return null
     */
    protected function requireEnv($variable, $message = null)
    {
        if ($this->_getEnv($variable) === false) {
            $msg = $message ? $message : sprintf(
                "This test requires the '%s' environment variable.",
                $this->_prefixEnvVariable($variable)
            );
            $this->markTestSkipped($msg);
        }
    }

    /**
     * @param string $variable
     *
     * @return string
     */
    protected function getEnv($variable)
    {
        $this->requireEnv($variable);
        return $this->_getEnv($variable);
    }

    private function _getEnv($variable)
    {
        return getenv($this->_prefixEnvVariable($variable));
    }

    private function _prefixEnvVariable($variable)
    {
        return 'PHPSECLIB_' . $variable;
    }
}
