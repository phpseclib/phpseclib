<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

error_reporting(E_ALL | E_STRICT);

// Ensure that composer has installed all dependencies
if (!file_exists(dirname(__DIR__) . DIRECTORY_SEPARATOR . '/vendor/autoload.php')) {
    die("Dependencies must be installed using composer:\n\nphp composer.phar install --dev\n\n"
        . "See http://getcomposer.org for help with installing composer\n");
}

// Include the Composer autoloader
$loader = include realpath(dirname(__FILE__) . '/../vendor/autoload.php');