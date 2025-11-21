<?php

/**
 * EC Parameters
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib4\Crypt\EC;

use phpseclib4\Crypt\EC;

/**
 * EC Parameters
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
final class Parameters extends EC
{
    /**
     * Returns the parameters
     *
     * @param array $options optional
     */
    public function toString(string $type = 'PKCS1', array $options = []): string
    {
        $type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

        return $type::saveParameters($this->curve, $options);
    }
}
