<?php

/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// declare(strict_types=1);

namespace phpseclib3\Tests;

abstract class PhpseclibFunctionalTestCase extends PhpseclibTestCase
{
    /**
     * @return null
     */
    protected function requireEnv(string $variable, string $message = null)
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
     *
     */
    protected function getEnv(string $variable): string
    {
        $this->requireEnv($variable);
        return $this->_getEnv($variable);
    }

    private function _getEnv($variable)
    {
        return getenv($this->_prefixEnvVariable($variable));
    }

    private function _prefixEnvVariable($variable): string
    {
        return 'PHPSECLIB_' . $variable;
    }
}
