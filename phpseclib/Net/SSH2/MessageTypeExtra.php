<?php

namespace phpseclib3\Net\SSH2;

/**
 * @internal
 */
abstract class MessageTypeExtra
{
    // RFC 4419 - diffie-hellman-group-exchange-sha{1,256}
    const KEXDH_GEX_REQUEST_OLD = 30;
    const KEXDH_GEX_GROUP = 31;
    const KEXDH_GEX_INIT = 32;
    const KEXDH_GEX_REPLY = 33;
    const KEXDH_GEX_REQUEST = 34;

    // RFC 5656 - Elliptic Curves (for curve25519-sha256@libssh.org)
    const KEX_ECDH_INIT = 30;
    const KEX_ECDH_REPLY = 31;

    const USERAUTH_PASSWD_CHANGEREQ = 60;

    const USERAUTH_PK_OK = 60;
}
