<?php

namespace phpseclib\Net\Exception;

use phpseclib\Exception\PhpSecLibException;
use phpseclib\Exception\PhpSecLibExceptionInterface;

class KeyExchangeFailedException extends PhpSecLibException implements PhpSecLibExceptionInterface
{
    public static function fromPayload($payload)
    {
        throw new self(
            sprintf(
                'The key exchange failed (Payload: %s)',
                $payload
            )
        );
    }

    public static function fromBadAlgorithm($badAlgorithm)
    {
        throw new self('Using a bad algorithm "%s"');
    }

    public static function fromUnreasonablePacketLength()
    {
        throw new self('Packet length during key exchange was unreasonable');
    }
}
