<?php

declare(strict_types=1);

namespace phpseclib4\Net\SSH2;

use phpseclib4\Common\ConstantUtilityTrait;

/**
 * @internal
 */
abstract class DisconnectReason
{
    use ConstantUtilityTrait;

    public const HOST_NOT_ALLOWED_TO_CONNECT = 1;
    public const PROTOCOL_ERROR = 2;
    public const KEY_EXCHANGE_FAILED = 3;
    public const RESERVED = 4;
    public const MAC_ERROR = 5;
    public const COMPRESSION_ERROR = 6;
    public const SERVICE_NOT_AVAILABLE = 7;
    public const PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    public const HOST_KEY_NOT_VERIFIABLE = 9;
    public const CONNECTION_LOST = 10;
    public const BY_APPLICATION = 11;
    public const TOO_MANY_CONNECTIONS = 12;
    public const AUTH_CANCELLED_BY_USER = 13;
    public const NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    public const ILLEGAL_USER_NAME = 15;
}
