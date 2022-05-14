<?php

// declare(strict_types=1);

namespace phpseclib3\Net\SFTP;

/**
 * http://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#section-6.3
 * the flag definitions change somewhat in SFTPv5+.  if SFTPv5+ support is added to this library, maybe name
 * the array for that $this->open5_flags and similarly alter the constant names.
 *
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
