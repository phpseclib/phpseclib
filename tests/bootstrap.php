<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

function phpseclib_autoload($class)
{
	$file = dirname( dirname( __FILE__ ) )."/phpseclib/".str_replace('_', '/', $class) . '.php';

	require $file;
}

spl_autoload_register('phpseclib_autoload');
