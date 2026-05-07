<?php

/**
 * ASN.1 Raw Element
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2014-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1;

/**
 * ASN.1 Raw Element
 *
 * An ASN.1 ANY mapping will return an ASN1\Element object. Use of this object
 * will also bypass the normal encoding rules in ASN1::encodeDER()
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class Element
{
    public array $metadata = [];

    /**
     * Constructor
     *
     * @return Element
     */
    public function __construct(public string $value)
    {
    }

    public function __debugInfo(): array
    {
        return ['value' => bin2hex($this->value)];
    }

    public function __toString(): string
    {
        return $this->value;
    }

    public function getEncoded(): string
    {
        return $this->value;
    }

    public function addMetadata(array $metadata): void
    {
        $this->metadata = $metadata;
    }
}
