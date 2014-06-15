<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

date_default_timezone_set('UTC');

require dirname(__FILE__) . DIRECTORY_SEPARATOR . 'Loader.php';
Loader::init(array('/home/travis/build/phpseclib/phpseclib/vendor'));
