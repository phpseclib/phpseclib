<?php

namespace phpseclib3\Net\SSH2;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class MessageType
{
    use ConstantUtilityTrait;

    const DISCONNECT = 1;
    const IGNORE = 2;
    const UNIMPLEMENTED = 3;
    const DEBUG = 4;
    const SERVICE_REQUEST = 5;
    const SERVICE_ACCEPT = 6;
    const EXT_INFO = 7;
    const NEWCOMPRESS = 8;

    const KEXINIT = 20;
    const NEWKEYS = 21;

    const USERAUTH_REQUEST = 50;
    const USERAUTH_FAILURE = 51;
    const USERAUTH_SUCCESS = 52;
    const USERAUTH_BANNER = 53;

    const USERAUTH_INFO_REQUEST = 60;
    const USERAUTH_INFO_RESPONSE = 61;

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
    const CHANNEL_FAILURE = 100;
}
