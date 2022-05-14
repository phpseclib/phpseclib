<?php

// declare(strict_types=1);

namespace phpseclib3\Net\SSH2;

/**
 * @internal
 */
abstract class ChannelConnectionFailureReason
{
    const ADMINISTRATIVELY_PROHIBITED = 1;
    const CONNECT_FAILED = 2;
    const UNKNOWN_CHANNEL_TYPE = 3;
    const RESOURCE_SHORTAGE = 4;
}
