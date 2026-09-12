<?php

/**
 * SSHChannelExitSignalException
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2015-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://phpseclib.com/
 */

declare(strict_types=1);

namespace phpseclib4\Exception;

/**
 * SSHChannelExitSignalException
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @psalm-suppress PossiblyUnusedProperty
 */
class SSHChannelExitSignalException extends UnexpectedValueException
{
    public string $partialOutput;

    public function __construct(
        public readonly string $signalName,
        public readonly bool $coreDumped,
        public readonly string $errorMessage
    ) {
        $message = 'Channel closed by server due to ' . $signalName;
        if ($coreDumped) {
            $message .= ' (core dumped)';
        }
        if (strlen($errorMessage)) {
            $message .= ': ' . $errorMessage;
        }
        parent::__construct($message);
    }
}
