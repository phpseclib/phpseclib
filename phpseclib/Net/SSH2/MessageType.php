<?php

declare(strict_types=1);

namespace phpseclib3\Net\SSH2;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class MessageType
{
    use ConstantUtilityTrait;

    public const DISCONNECT = 1;
    public const IGNORE = 2;
    public const UNIMPLEMENTED = 3;
    public const DEBUG = 4;
    public const SERVICE_REQUEST = 5;
    public const SERVICE_ACCEPT = 6;
    public const EXT_INFO = 7;
    public const NEWCOMPRESS = 8;

    public const KEXINIT = 20;
    public const NEWKEYS = 21;

    // KEXDH_INIT and KEXDH_REPLY are not defined RFC4250 but are referenced in RFC4253
    public const KEXDH_INIT = 30;
    public const KEXDH_REPLY = 31;

    public const USERAUTH_REQUEST = 50;
    public const USERAUTH_FAILURE = 51;
    public const USERAUTH_SUCCESS = 52;
    public const USERAUTH_BANNER = 53;

    public const USERAUTH_INFO_REQUEST = 60;
    public const USERAUTH_INFO_RESPONSE = 61;

    public const GLOBAL_REQUEST = 80;
    public const REQUEST_SUCCESS = 81;
    public const REQUEST_FAILURE = 82;

    public const CHANNEL_OPEN = 90;
    public const CHANNEL_OPEN_CONFIRMATION = 91;
    public const CHANNEL_OPEN_FAILURE = 92;
    public const CHANNEL_WINDOW_ADJUST = 93;
    public const CHANNEL_DATA = 94;
    public const CHANNEL_EXTENDED_DATA = 95;
    public const CHANNEL_EOF = 96;
    public const CHANNEL_CLOSE = 97;
    public const CHANNEL_REQUEST = 98;
    public const CHANNEL_SUCCESS = 99;
    public const CHANNEL_FAILURE = 100;
}
