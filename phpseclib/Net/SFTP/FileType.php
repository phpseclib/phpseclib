<?php

declare(strict_types=1);

namespace phpseclib3\Net\SFTP;

/**
 * http://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#section-5.2
 * see \phpseclib3\Net\SFTP::_parseLongname() for an explanation
 *
 * @internal
 */
abstract class FileType
{
    public const REGULAR = 1;
    public const DIRECTORY = 2;
    public const SYMLINK = 3;
    public const SPECIAL = 4;
    public const UNKNOWN = 5;
    // the following types were first defined for use in SFTPv5+
    // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-05#section-5.2
    public const SOCKET = 6;
    public const CHAR_DEVICE = 7;
    public const BLOCK_DEVICE = 8;
    public const FIFO = 9;
}
