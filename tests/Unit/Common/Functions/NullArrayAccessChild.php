<?php

/**
 * @author    phpseclib contributors
 * @copyright 2026 phpseclib contributors
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Common\Functions;

class NullArrayAccessChild implements \ArrayAccess
{
    private mixed $value = null;

    public function offsetExists(mixed $offset): bool
    {
        return true;
    }

    public function &offsetGet(mixed $offset): mixed
    {
        return $this->value;
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->value = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->value = null;
    }
}
