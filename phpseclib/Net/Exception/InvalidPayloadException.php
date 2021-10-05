<?php

namespace phpseclib\Net\Exception;

use phpseclib\Exception\PhpSecLibExceptionInterface;

class InvalidPayloadException extends NetException implements PhpSecLibExceptionInterface
{
    public static function payloadTooShortException($payload, $expectedBits)
    {
        throw new self(
            sprintf(
                'The payload "%s" was too short (is: %d bits, should be at least: %d bits)',
                $payload,
                strlen($payload),
                $expectedBits
            )
        );
    }
}
