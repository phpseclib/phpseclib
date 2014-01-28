<?php
/**
 * Bootstrapping File for phpseclib Test Suite
 *
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

date_default_timezone_set('UTC');

// Set up include path accordingly. This is especially required because some
// class files of phpseclib require() other dependencies.
set_include_path(implode(PATH_SEPARATOR, array(
	realpath(dirname(__FILE__) . '/../phpseclib'),
	realpath(dirname(__FILE__) . '/../tests'),
	realpath(dirname(__FILE__) . '/'),
	get_include_path(),
)));

function phpseclib_autoload($class)
{
	$file = str_replace('\\', '/', $class) . '.php';
	
	foreach (explode(PATH_SEPARATOR, get_include_path()) as $prefix)
	{
		$ds = substr($prefix, -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR;
		$path = $prefix . $ds . str_replace('phpseclib/', '', $file);
		
		if (file_exists($path))
		{
			require $path;
			return;
		}
	}
}

spl_autoload_register('phpseclib_autoload');
