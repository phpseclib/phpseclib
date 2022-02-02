<?php

namespace phpseclib3\Net\SFTP;

/**
 * @internal
 */
abstract class FileType
{
    const REGULAR = 1;
    const DIRECTORY = 2;
    const SYMLINK = 3;
    const SPECIAL = 4;
    const UNKNOWN = 5;
    // the following types were first defined for use in SFTPv5+
    // http://tools.ietf.org/html/draft-ietf-secsh-filexfer-05#section-5.2
    const SOCKET = 6;
    const CHAR_DEVICE = 7;
    const BLOCK_DEVICE = 8;
    const FIFO = 9;
}
