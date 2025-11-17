<?php

/**
 * OID (Object Identifier)
 *
 * PHP version 5
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

declare(strict_types=1);

namespace phpseclib3\File\ASN1\Types;

use phpseclib3\File\ASN1;

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
     *
     * @return Element
     */
    public function __construct(public string $value)
    {
        $this->tryToSetName();
    }

    public function __debugInfo(): array
    {
        $output = ['value' => $this->value];
        $this->tryToSetName();
        if (isset($this->name)) {
            $output['name'] = $this->name;
        }
        return $output;
    }

    public function __toString(): string
    {
        $this->tryToSetName();
        return $this->name ?? $this->value;
    }

    private function tryToSetName()
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
