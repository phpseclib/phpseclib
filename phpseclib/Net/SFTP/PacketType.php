<?php

declare(strict_types=1);

namespace phpseclib4\Net\SFTP;

use phpseclib4\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class PacketType
{
    use ConstantUtilityTrait;

    public const INIT = 1;
    public const VERSION = 2;
    public const OPEN = 3;
    public const CLOSE = 4;
    public const READ = 5;
    public const WRITE = 6;
    public const LSTAT = 7;
    public const SETSTAT = 9;
    public const FSETSTAT = 10;
    public const OPENDIR = 11;
    public const READDIR = 12;
    public const REMOVE = 13;
    public const MKDIR = 14;
    public const RMDIR = 15;
    public const REALPATH = 16;
    public const STAT = 17;
    public const RENAME = 18;
    public const READLINK = 19;
    public const SYMLINK = 20;
    public const LINK = 21;

    public const STATUS = 101;
    public const HANDLE = 102;
    public const DATA = 103;
    public const NAME = 104;
    public const ATTRS = 105;

    public const EXTENDED = 200;
    public const EXTENDED_REPLY = 201;
}
