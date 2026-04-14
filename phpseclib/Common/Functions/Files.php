<?php

/**
 * Common File Functions
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2016 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Common\Functions;

use phpseclib4\Exception\FileSystemException;

/**
 * Common File Functions
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class Files
{
    /**
     * Safely open a file
     *
     * @return resource
     */
    public static function open(string $filename, string $mode)
    {
        set_error_handler(function ($errno, $errstr) use ($filename): void {
            throw new FileSystemException("Failed to open '$filename': $errstr");
        });

        try {
            $fp = @fopen($filename, $mode);
            if ($fp === false) {
                throw new FileSystemException("fopen returned false for $filename");
            }
            return $fp;
        } finally {
            restore_error_handler();
        }
    }
}
