<?php

declare(strict_types=1);

namespace phpseclib4\Exception;

/**
 * Indicates an absent or malformed packet length header
 */
class InvalidPacketLengthException extends ConnectionClosedException
{
}
