<?php

declare(strict_types=1);

namespace Matchory\IdMask\Entropy;

use Exception;
use Matchory\IdMask\Exception\NotEnoughEntropyException;

use function random_bytes;

/**
 * Entropy Source
 *
 * Default entropy source implementation.
 *
 * @bundle Matchory\IdMask
 * @internal
 */
class EntropySource implements EntropySourceInterface
{
    /**
     * @inheritDoc
     */
    public function generate(int $length): string
    {
        try {
            return random_bytes($length);
        } catch (Exception $exception) {
            throw NotEnoughEntropyException::from($exception);
        }
    }
}
