<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright MMXIV Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

abstract class PhpseclibFunctionalTestCase extends PhpseclibTestCase
{
    static public function setUpBeforeClass()
    {
        if (extension_loaded('runkit')) {
            self::ensureConstant('MATH_BIGINTEGER_MODE', MATH_BIGINTEGER_MODE_GMP);
            self::ensureConstant('CRYPT_HASH_MODE', CRYPT_HASH_MODE_HASH);
            self::reRequireFile('Math/BigInteger.php');
            self::reRequireFile('Crypt/Hash.php');
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
