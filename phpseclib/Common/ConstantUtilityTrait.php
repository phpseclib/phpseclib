<?php

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
     * @return string|null
     */
    public static function findConstantNameByValue($value)
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
     * @return string
     */
    public static function getConstantNameByValue($value)
    {
        $constantName = static::findConstantNameByValue($value);
        if ($constantName === null) {
            throw new \InvalidArgumentException(sprintf('"%s" does not have constant with value "%s".', static::class, $value));
        }
        return $constantName;
    }
}
