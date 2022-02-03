<?php

namespace phpseclib3\Net\Ssh2;

use phpseclib3\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class DisconnectReason
{
    use ConstantUtilityTrait;

    const HOST_NOT_ALLOWED_TO_CONNECT = 1;
    const PROTOCOL_ERROR = 2;
    const KEY_EXCHANGE_FAILED = 3;
    const RESERVED = 4;
    const MAC_ERROR = 5;
    const COMPRESSION_ERROR = 6;
    const SERVICE_NOT_AVAILABLE = 7;
    const PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    const HOST_KEY_NOT_VERIFIABLE = 9;
    const CONNECTION_LOST = 10;
    const BY_APPLICATION = 11;
    const TOO_MANY_CONNECTIONS = 12;
    const AUTH_CANCELLED_BY_USER = 13;
    const NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    const ILLEGAL_USER_NAME = 15;
}
