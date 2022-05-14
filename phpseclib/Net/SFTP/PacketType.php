<?php

// declare(strict_types=1);

namespace phpseclib3\Net\SFTP;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class PacketType
{
    use ConstantUtilityTrait;

    const INIT = 1;
    const VERSION = 2;
    const OPEN = 3;
    const CLOSE = 4;
    const READ = 5;
    const WRITE = 6;
    const LSTAT = 7;
    const SETSTAT = 9;
    const FSETSTAT = 10;
    const OPENDIR = 11;
    const READDIR = 12;
    const REMOVE = 13;
    const MKDIR = 14;
    const RMDIR = 15;
    const REALPATH = 16;
    const STAT = 17;
    const RENAME = 18;
    const READLINK = 19;
    const SYMLINK = 20;
    const LINK = 21;

    const STATUS = 101;
    const HANDLE = 102;
    const DATA = 103;
    const NAME = 104;
    const ATTRS = 105;

    const EXTENDED = 200;
}
