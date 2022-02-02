<?php

namespace phpseclib3\Net\SFTP;

/**
 * @internal
 */
abstract class OpenFlag
{
    const READ = 0x00000001;
    const WRITE = 0x00000002;
    const APPEND = 0x00000004;
    const CREATE = 0x00000008;
    const TRUNCATE = 0x00000010;
    const EXCL = 0x00000020;
    const TEXT = 0x00000040; // defined in SFTPv4
}
