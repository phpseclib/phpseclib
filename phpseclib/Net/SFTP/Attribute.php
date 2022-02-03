<?php

namespace phpseclib3\Net\SFTP;

/**
 * http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-7.1
 * the order, in this case, matters quite a lot - see \phpseclib3\Net\SFTP::_parseAttributes() to understand why
 *
 * @internal
 */
abstract class Attribute
{
    const SIZE = 0x00000001;
    const UIDGID = 0x00000002;          // defined in SFTPv3, removed in SFTPv4+
    const OWNERGROUP = 0x00000080;      // defined in SFTPv4+
    const PERMISSIONS = 0x00000004;
    const ACCESSTIME = 0x00000008;
    const CREATETIME = 0x00000010;      // SFTPv4+
    const MODIFYTIME = 0x00000020;
    const ACL = 0x00000040;
    const SUBSECOND_TIMES = 0x00000100;
    const BITS = 0x00000200;            // SFTPv5+
    const ALLOCATION_SIZE = 0x00000400; // SFTPv6+
    const TEXT_HINT = 0x00000800;
    const MIME_TYPE = 0x00001000;
    const LINK_COUNT = 0x00002000;
    const UNTRANSLATED_NAME = 0x00004000;
    const CTIME = 0x00008000;
    // 0x80000000 will yield a floating point on 32-bit systems and converting floating points to integers
    // yields inconsistent behavior depending on how php is compiled.  so we left shift -1 (which, in
    // two's compliment, consists of all 1 bits) by 31.  on 64-bit systems this'll yield 0xFFFFFFFF80000000.
    // that's not a problem, however, and 'anded' and a 32-bit number, as all the leading 1 bits are ignored.
    const EXTENDED = (-1 << 31) & 0xFFFFFFFF;

    /**
     * @return array
     */
    public static function getConstants()
    {
        $reflectionClass = new \ReflectionClass(static::class);
        return $reflectionClass->getConstants();
    }
}
