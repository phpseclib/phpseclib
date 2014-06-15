<?php
/*!
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *               PACKAGE : PHP POWERTOOLS
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *               COMPONENT : AUTOLOADER 
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 
 *               DESCRIPTION :
 *
 *               Zero configuration autoloader for Symfony components, 
 *               Zend components, and other PSR-0 compatible libraries
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 
 *               REQUIREMENTS :
 *
 *               PHP version 5.3+
 *               PSR-0 compatibility
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 
 *               EXAMPLE :
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    define("BASE_PATH", dirname(__FILE__));
 *    define("LIBRARY_PATH", BASE_PATH . DIRECTORY_SEPARATOR . 'vendor');
 *    define("USER_PATH", BASE_PATH . DIRECTORY_SEPARATOR . 'user123');
 * 
 *    require LIBRARY_PATH . DIRECTORY_SEPARATOR . 'Loader.php';
 *    Loader::init(array(LIBRARY_PATH, USER_PATH));
 *
 * ?>
 * </code>
 * 
 * If you include the code hereabove, the paths /vendor and /user123
 * will be added to the include path.
 * 
 * Any PSR-0 compliant classes will now automatically be loaded from /user123.
 * 
 * If it can't be found there, the autoloader will attempt to locate it at the 
 * /vendor path
 *
 * It requires no additional configuration and does not require composer.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 
 *               LICENSE :
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  @category  Autoloader
 *  @package   /
 *  @author    John Slegers
 *  @copyright MMXIV John Slegers
 *  @license   http://www.opensource.org/licenses/mit-license.html MIT License
 *  @link      https://github.com/jslegers
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/



class Loader {

    protected static $_static_data = array();

    public static function init($prependPaths = array()) {
        static::setErrorReporting(!true);
        static::_synchPaths(true);
        static::appendLoader(get_called_class(), 'load');
        static::prependPaths($prependPaths);
    }

    public static function setErrorReporting($enable = true) {
        if ($enable) {
            error_reporting(E_ALL ^ E_NOTICE);
            ini_set('display_errors', 1);
        } else {
            error_reporting(0);
            ini_set('display_errors', 0);
        }
    }

    public static function load($className) {
        $className = ltrim($className, '\\');
        $fileName = '';
        $namespace = '';
        if ($lastNsPos = strrpos($className, '\\')) {
            $namespace = substr($className, 0, $lastNsPos);
            $className = substr($className, $lastNsPos + 1);
            $fileName = str_replace('\\', DIRECTORY_SEPARATOR, $namespace) . DIRECTORY_SEPARATOR;
        }
        $fileName .= str_replace('_', DIRECTORY_SEPARATOR, $className) . '.php';

        foreach ($paths = static::getPaths() as $path) {
            $fullpath = $path . DIRECTORY_SEPARATOR . $fileName;
            if (is_readable($fullpath)) {
            //    var_dump($fullpath);
                require $fullpath;
                break;
            }
        }
    }

    public static function appendLoader($class, $method) {
        static::_registerLoader($class, $method, false);
    }

    public static function prependLoader($class, $method) {
        static::_registerLoader($class, $method, true);
    }

    protected static function _registerLoader($class, $method, $prepend = false) {
        spl_autoload_register(array($class, $method), true, $prepend);
    }

    public static function removeLoader($class, $method) {
        spl_autoload_unregister(array($class, $method));
    }

    public static function getPaths() {
        return static::$_static_data['includepaths'];
    }

    public static function setPaths(array $paths) {
        static::$_static_data['includepaths'] = $paths;
        static::_synchPaths();
    }

    public static function prependPath($path) {
        static::_prepend($path);
    }

    public static function prependPaths(array $paths) {
        static::_repeat('_prepend', $paths);
    }

    protected static function _prepend($path, $synch = true) {
        static::removePath($path, false);
        array_unshift(static::$_static_data['includepaths'], $path);
        if ($synch)
            static::_synchPaths();
    }

    public static function appendPath($path) {
        static::_append($path);
    }

    public static function appendPaths(array $paths) {
        static::_repeat('_append', $paths);
    }

    protected static function _append($path, $synch = true) {
        static::removePath($path, false);
        static::$_static_data['includepaths'][] = $path;
        if ($synch)
            static::_synchPaths();
    }

    public static function removePath($path) {
        static::_remove($path);
    }

    public static function removePaths(array $paths) {
        static::_repeat('_remove', $paths);
    }

    protected static function _remove($path, $synch = true) {
        if (($key = array_search($path, static::$_static_data['includepaths'])) !== false) {
            unset(static::$_static_data['includepaths'][$key]);
            if ($synch)
                static::_synchPaths();
        }
    }

    protected static function _repeat($method, array $paths) {
        foreach ($paths as $path) {
            static::$method($path, false);
        }
        static::_synchPaths();
    }

    protected static function _synchPaths($reverse = false) {
        if ($reverse) {
            static::$_static_data['includepaths'] = explode(PATH_SEPARATOR, get_include_path());
        } else {
            set_include_path(implode(PATH_SEPARATOR, static::$_static_data['includepaths']));
        }
    }
}
?>
