<?php

/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

date_default_timezone_set('UTC');

$loader_path = __DIR__ . '/../vendor/autoload.php';
if (!file_exists($loader_path)) {
    exit(<<<EOF
Dependencies must be installed using composer:
    php composer.phar install
See https://getcomposer.org for help with installing composer.

EOF
    );
}

require $loader_path;
