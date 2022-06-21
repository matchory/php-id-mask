<?php

declare(strict_types=1);

namespace Matchory\IdMask\Exception;

class DecryptionException extends UnmaskingException
{
    public static function from(string|false $message): self
    {
        $message = $message ?: 'Unknown error';

        return new self("Failed to decrypt cipher: {$message}");
    }
}
