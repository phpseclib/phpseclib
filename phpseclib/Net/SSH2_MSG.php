<?php

namespace phpseclib\Net;

use phpseclib\Common\Enum;

class SSH2_MSG extends Enum
{
    const DISCONNECT = 1;
    const IGNORE = 2;
    const UNIMPLEMENTED = 3;
    const DEBUG = 4;
    const SERVICE_REQUEST = 5;
    const SERVICE_ACCEPT = 6;
    const KEXINIT = 20;
    const NEWKEYS = 21;
    const KEXDH_INIT = 30;
    const KEXDH_REPLY = 31;
    const USERAUTH_REQUEST = 50;
    const USERAUTH_FAILURE = 51;
    const USERAUTH_SUCCESS = 52;
    const USERAUTH_BANNER = 53;
    
    const GLOBAL_REQUEST = 80;
    const REQUEST_SUCCESS = 81;
    const REQUEST_FAILURE = 82;
    const CHANNEL_OPEN = 90;
    const CHANNEL_OPEN_CONFIRMATION = 91;
    const CHANNEL_OPEN_FAILURE = 92;
    const CHANNEL_WINDOW_ADJUST = 93;
    const CHANNEL_DATA = 94;
    const CHANNEL_EXTENDED_DATA = 95;
    const CHANNEL_EOF = 96;
    const CHANNEL_CLOSE = 97;
    const CHANNEL_REQUEST = 98;
    const CHANNEL_SUCCESS = 99;
    const CHANNEL_FAILURE=100;
    
    const USERAUTH_PASSWD_CHANGEREQ = 60;
    const USERAUTH_PK_OK = 60;
    const USERAUTH_INFO_REQUEST = 60;
    const USERAUTH_INFO_RESPONSE = 61;
        // RFC 4419 - diffie-hellman-group-exchange-sha{1,256}
    const KEXDH_GEX_REQUEST_OLD = 30;
    const KEXDH_GEX_GROUP = 31;
    const KEXDH_GEX_INIT = 32;
    const KEXDH_GEX_REPLY = 33;
    const KEXDH_GEX_REQUEST = 34;
        // RFC 5656 - Elliptic Curves (for curve25519-sha256@libssh.org)
    const KEX_ECDH_INIT = 30;
    const KEX_ECDH_REPLY = 31;
}
