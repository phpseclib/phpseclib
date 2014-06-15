<?php
$LIBRARY_PATH = dirname(__FILE__) . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .'vendors';
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

date_default_timezone_set('UTC');

require $LIBRARY_PATH . DIRECTORY_SEPARATOR . 'Loader.php';
Loader::init(array($LIBRARY_PATH));
