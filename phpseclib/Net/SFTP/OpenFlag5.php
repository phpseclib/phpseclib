<?php

declare(strict_types=1);

namespace phpseclib3\Net\SFTP;

/**
 * SFTPv5+ changed the flags up: https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-8.1.1.3
 *
 * @internal
 */
abstract class OpenFlag5
{
    // when SSH_FXF_ACCESS_DISPOSITION is a 3 bit field that controls how the file is opened
    public const CREATE_NEW = 0x00000000;
    public const CREATE_TRUNCATE = 0x00000001;
    public const OPEN_EXISTING = 0x00000002;
    public const OPEN_OR_CREATE = 0x00000003;
    public const TRUNCATE_EXISTING = 0x00000004;
    // the rest of the flags are not supported
    public const APPEND_DATA = 0x00000008; // "the offset field of SS_FXP_WRITE requests is ignored"
    public const APPEND_DATA_ATOMIC = 0x00000010;
    public const TEXT_MODE = 0x00000020;
    public const BLOCK_READ = 0x00000040;
    public const BLOCK_WRITE = 0x00000080;
    public const BLOCK_DELETE = 0x00000100;
    public const BLOCK_ADVISORY = 0x00000200;
    public const NOFOLLOW = 0x00000400;
    public const DELETE_ON_CLOSE = 0x00000800;
    public const ACCESS_AUDIT_ALARM_INFO = 0x00001000;
    public const ACCESS_BACKUP = 0x00002000;
    public const BACKUP_STREAM = 0x00004000;
    public const OVERRIDE_OWNER = 0x00008000;
}
