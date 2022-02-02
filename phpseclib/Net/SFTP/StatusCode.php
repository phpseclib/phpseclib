<?php

namespace phpseclib3\Net\SFTP;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class StatusCode
{
    use ConstantUtilityTrait;

    const OK = 0;
    const EOF = 1;
    const NO_SUCH_FILE = 2;
    const PERMISSION_DENIED = 3;
    const FAILURE = 4;
    const BAD_MESSAGE = 5;
    const NO_CONNECTION = 6;
    const CONNECTION_LOST = 7;
    const OP_UNSUPPORTED = 8;
    const INVALID_HANDLE = 9;
    const NO_SUCH_PATH = 10;
    const FILE_ALREADY_EXISTS = 11;
    const WRITE_PROTECT = 12;
    const NO_MEDIA = 13;
    const NO_SPACE_ON_FILESYSTEM = 14;
    const QUOTA_EXCEEDED = 15;
    const UNKNOWN_PRINCIPAL = 16;
    const LOCK_CONFLICT = 17;
    const DIR_NOT_EMPTY = 18;
    const NOT_A_DIRECTORY = 19;
    const INVALID_FILENAME = 20;
    const LINK_LOOP = 21;
    const CANNOT_DELETE = 22;
    const INVALID_PARAMETER = 23;
    const FILE_IS_A_DIRECTORY = 24;
    const BYTE_RANGE_LOCK_CONFLICT = 25;
    const BYTE_RANGE_LOCK_REFUSED = 26;
    const DELETE_PENDING = 27;
    const FILE_CORRUPT = 28;
    const OWNER_INVALID = 29;
    const GROUP_INVALID = 30;
    const NO_MATCHING_BYTE_RANGE_LOCK = 31;
}
