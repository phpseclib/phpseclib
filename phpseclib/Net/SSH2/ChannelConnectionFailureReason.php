<?php

declare(strict_types=1);

namespace phpseclib3\Net\SSH2;

/**
 * @internal
 */
abstract class ChannelConnectionFailureReason
{
    public const ADMINISTRATIVELY_PROHIBITED = 1;
    public const CONNECT_FAILED = 2;
    public const UNKNOWN_CHANNEL_TYPE = 3;
    public const RESOURCE_SHORTAGE = 4;
}
