<?php

/**
 * OID (Object Identifier)
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2025-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\File\ASN1\Types;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Element;

/**
 * OID (Object Identifier)
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class OID implements BaseType
{
    use Common;

    public const TYPE = 6;

    public string $name;

    /**
     * Constructor
     */
    public function __construct(public string|Element $value)
    {
        //$this->tryToSetName();
    }

    public function __debugInfo(): array
    {
        if ($this->value instanceof Element) {
            $this->value = ASN1::decodeOID($this->value->value)->value;
        }
        $output = ['value' => $this->value];
        $this->tryToSetName();
        if (isset($this->name)) {
            $output['name'] = $this->name;
        }
        return $output;
    }

    public function __toString(): string
    {
        if ($this->value instanceof Element) {
            $this->value = ASN1::decodeOID($this->value->value)->value;
        }
        $this->tryToSetName();
        return $this->name ?? $this->value;
    }

    private function tryToSetName(): void
    {
        if (!isset($this->name)) {
            if (preg_match('#^\d[\d\.]+\d$#', $this->value)) {
                $temp = ASN1::getNameFromOID($this->value);
                if ($temp != $this->value) {
                    $this->name = $temp;
                }
            } else {
                $temp = ASN1::getOIDFromName($this->value);
                if ($temp != $this->value) {
                    $this->name = $this->value;
                    $this->value = $temp;
                }
            }
        }
    }
}
