<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

date_default_timezone_set('UTC');

$loader_path = __DIR__ . '/../vendor/autoload.php';
if (!file_exists($loader_path)) {
    echo "Dependencies must be installed using composer:\n\n";
    echo "php composer.phar install\n\n";
    echo "See http://getcomposer.org for help with installing composer\n";
    exit(1);
}

$loader = include $loader_path;
$loader->add('', __DIR__);
