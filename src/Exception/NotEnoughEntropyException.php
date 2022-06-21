<?php

declare(strict_types=1);

namespace Matchory\IdMask\Exception;

use RuntimeException;
use Throwable;

use function assert;
use function is_int;

/**
 * Not Enough Entropy Exception
 *
 * @bundle Matchory\IdMask
 */
final class NotEnoughEntropyException extends RuntimeException
{
    public static function from(Throwable $exception): NotEnoughEntropyException
    {
        $message = "Failed to generate entropy: {$exception->getMessage()}";
        $code = $exception->getCode();

        assert(is_int($code));

        return new self($message, $code, $exception);
    }
}
