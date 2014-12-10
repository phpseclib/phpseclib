<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

date_default_timezone_set('UTC');

// Set up include path accordingly. This is especially required because some
// class files of phpseclib require() other dependencies.
set_include_path(implode(PATH_SEPARATOR, array(
    dirname(__FILE__) . '/../phpseclib/',
    dirname(__FILE__) . '/',
    get_include_path(),
)));

require_once 'Crypt/Random.php';

function phpseclib_class2file($class)
{
    return str_replace('_', '/', $class) . '.php';
}

function phpseclib_autoload($class)
{
    $file = phpseclib_class2file($class);

    if (phpseclib_resolve_include_path($file)) {
        // @codingStandardsIgnoreStart
        require $file;
        // @codingStandardsIgnoreEnd
    }
}

spl_autoload_register('phpseclib_autoload');
