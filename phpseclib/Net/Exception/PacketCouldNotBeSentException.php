<?php

namespace phpseclib\Net\Exception;

use phpseclib\Exception\PhpSecLibExceptionInterface;

class PacketCouldNotBeSentException extends NetException implements PhpSecLibExceptionInterface
{
    public static function fromPacket($packet)
    {
        throw new self(
            sprintf(
                'The package could not be sent (Content: %s)',
                $packet
            )
        );
    }
}
