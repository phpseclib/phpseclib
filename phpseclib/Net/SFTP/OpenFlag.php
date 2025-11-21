<?php

declare(strict_types=1);

namespace phpseclib4\Net\SFTP;

/**
 * http://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#section-6.3
 * the flag definitions change somewhat in SFTPv5+.  if SFTPv5+ support is added to this library, maybe name
 * the array for that $this->open5_flags and similarly alter the constant names.
 *
 * @internal
 */
abstract class OpenFlag
{
    public const READ = 0x00000001;
    public const WRITE = 0x00000002;
    public const APPEND = 0x00000004;
    public const CREATE = 0x00000008;
    public const TRUNCATE = 0x00000010;
    public const EXCL = 0x00000020;
    public const TEXT = 0x00000040; // defined in SFTPv4
}
