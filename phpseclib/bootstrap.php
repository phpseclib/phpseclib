<?php

/**
 * Bootstrapping File for phpseclib
 *
 * composer isn't a requirement for phpseclib 2.0 but this file isn't really required
 * either. it's a bonus for those using composer but if you're not phpseclib will
 * still work
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

if (extension_loaded('mbstring')) {
    // 2 - MB_OVERLOAD_STRING
    // mbstring.func_overload is deprecated in php 7.2 and removed in php 8.0.
    if (version_compare(PHP_VERSION, '8.0.0') < 0 && ini_get('mbstring.func_overload') & 2) {
        throw new UnexpectedValueException(
            'Overloading of string functions using mbstring.func_overload ' .
            'is not supported by phpseclib.'
        );
    }
}

// see https://github.com/php/php-src/issues/11917
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && function_exists('opcache_get_status') && !defined('PHPSECLIB_ALLOW_JIT')) {
    $status = opcache_get_status();
    if ($status && $status['jit']['enabled'] && $status['jit']['on']) {
        throw new UnexpectedValueException(
            'JIT on Windows is not currently supported'
        );
    }
}
