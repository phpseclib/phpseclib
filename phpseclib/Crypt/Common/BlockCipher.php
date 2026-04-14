<?php

/**
 * Base Class for all block ciphers
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\Common;

use phpseclib4\Exception\InvalidArgumentException;

/**
 * Base Class for all block cipher classes
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
abstract class BlockCipher extends SymmetricKey
{
    /**
     * Default Constructor.
     */
    public function __construct(string $mode)
    {
        parent::__construct($mode);

        if ($this->mode == self::MODE_STREAM) {
            throw new InvalidArgumentException('Block ciphers cannot be ran in stream mode');
        }
    }
}
