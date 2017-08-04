<?php

namespace phpseclib\Common;

abstract class Enum
{
    protected static $constants=null;

    protected static function init()
    {
        if (self::$constants==null) {
            $reflect = new \ReflectionClass(get_called_class());

            self::$constants = $reflect->getConstants();
        }
    }

    public static function val($name)
    {
        return constant("static::$name");
    }

    public static function names($val)
    {
        self::init();
        $res=array_keys(self::$constants, $val);

        return $res;
    }

    public static function name($val)
    {
        return self::names($val)[0];
    }

    public static function valueExists($val)
    {
        self::init();
        return array_search($val,self::$constants)!==false;
    }

    public static function constExists($name)
    {
        self::init();
        return (isset(self::$constants[$name]));
    }
}
