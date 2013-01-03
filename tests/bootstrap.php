<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

// Set up include path accordingly. This is especially required because some
// class files of phpseclib require() other dependencies.
set_include_path(implode(PATH_SEPARATOR, array(
	dirname(__FILE__) . '/../phpseclib/',
	dirname(__FILE__) . '/',
	get_include_path(),
)));

function phpseclib_is_includable($suffix)
{
	foreach (explode(PATH_SEPARATOR, get_include_path()) as $prefix)
	{
		$ds = substr($prefix, -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR;
		$file = $prefix . $ds . $suffix;

		if (file_exists($file))
		{
			return true;
		}
	}

	return false;
}

function phpseclib_autoload($class)
{
	$file = str_replace('_', '/', $class) . '.php';

	if (phpseclib_is_includable($file))
	{
		require $file;
	}
}

spl_autoload_register('phpseclib_autoload');
