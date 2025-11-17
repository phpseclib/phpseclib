<?php

/**
 * EncodedDataUnavailableException
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\Exception;

/**
 * EncodedDataUnavailableException
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class EncodedDataUnavailableException extends \RuntimeException implements ExceptionInterface
{
    public ?array $meta = null;

    public function addMetadata(array $meta): void
    {
        $this->meta = $meta;
    }
}
