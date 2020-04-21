<?php

namespace phpseclib\Net\Exception;

use phpseclib\Exception\PhpSecLibException;
use phpseclib\Exception\PhpSecLibExceptionInterface;

class NetException extends PhpSecLibException implements PhpSecLibExceptionInterface
{
    public static function withMessage($message)
    {
        throw new self($message);
    }
}
