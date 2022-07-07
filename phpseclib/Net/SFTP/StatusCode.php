<?php

declare(strict_types=1);

namespace phpseclib3\Net\SFTP;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class StatusCode
{
    use ConstantUtilityTrait;

    public const OK = 0;
    public const EOF = 1;
    public const NO_SUCH_FILE = 2;
    public const PERMISSION_DENIED = 3;
    public const FAILURE = 4;
    public const BAD_MESSAGE = 5;
    public const NO_CONNECTION = 6;
    public const CONNECTION_LOST = 7;
    public const OP_UNSUPPORTED = 8;
    public const INVALID_HANDLE = 9;
    public const NO_SUCH_PATH = 10;
    public const FILE_ALREADY_EXISTS = 11;
    public const WRITE_PROTECT = 12;
    public const NO_MEDIA = 13;
    public const NO_SPACE_ON_FILESYSTEM = 14;
    public const QUOTA_EXCEEDED = 15;
    public const UNKNOWN_PRINCIPAL = 16;
    public const LOCK_CONFLICT = 17;
    public const DIR_NOT_EMPTY = 18;
    public const NOT_A_DIRECTORY = 19;
    public const INVALID_FILENAME = 20;
    public const LINK_LOOP = 21;
    public const CANNOT_DELETE = 22;
    public const INVALID_PARAMETER = 23;
    public const FILE_IS_A_DIRECTORY = 24;
    public const BYTE_RANGE_LOCK_CONFLICT = 25;
    public const BYTE_RANGE_LOCK_REFUSED = 26;
    public const DELETE_PENDING = 27;
    public const FILE_CORRUPT = 28;
    public const OWNER_INVALID = 29;
    public const GROUP_INVALID = 30;
    public const NO_MATCHING_BYTE_RANGE_LOCK = 31;
}
