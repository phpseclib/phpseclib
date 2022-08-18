<?php

declare(strict_types=1);

namespace phpseclib3\Common;

/**
 * @internal
 */
trait ConstantUtilityTrait
{
    /** @var string[]|null */
    private static $valueToConstantNameMap = null;

    /**
     * @param string|int $value
     */
    public static function findConstantNameByValue($value): ?string
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

    /**
     * @param string|int $value
     */
    public static function getConstantNameByValue($value): string
    {
        $constantName = static::findConstantNameByValue($value);
        if ($constantName === null) {
            throw new \phpseclib3\Exception\InvalidArgumentException(sprintf('"%s" does not have constant with value "%s".', static::class, $value));
        }
        return $constantName;
    }
}
