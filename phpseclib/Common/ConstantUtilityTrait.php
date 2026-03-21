<?php

declare(strict_types=1);

namespace phpseclib4\Common;

use phpseclib4\Exception\InvalidArgumentException;

/**
 * @internal
 */
trait ConstantUtilityTrait
{
    /** @var string[]|null */
    private static ?array $valueToConstantNameMap = null;

    public static function findConstantNameByValue(string|int $value): ?string
    {
        if (!self::$valueToConstantNameMap) {
            $reflectionClass = new \ReflectionClass(static::class);
            $constantNameToValueMap = $reflectionClass->getConstants();
            self::$valueToConstantNameMap = array_flip($constantNameToValueMap);
        }
        if (isset(self::$valueToConstantNameMap[$value])) {
            return self::$valueToConstantNameMap[$value];
        }
        return null;
    }

    public static function getConstantNameByValue(string|int $value): string
    {
        $constantName = static::findConstantNameByValue($value);
        if ($constantName === null) {
            throw new InvalidArgumentException(sprintf('"%s" does not have constant with value "%s".', static::class, $value));
        }
        return $constantName;
    }
}
