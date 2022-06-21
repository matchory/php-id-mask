<?php

declare(strict_types=1);

namespace Matchory\IdMask\Exception;

class EncryptionException extends MaskingException
{
    public static function from(string|false $message): self
    {
        $message = $message ?: 'Unknown error';

        return new self("Failed to encrypt cipher: {$message}");
    }
}
