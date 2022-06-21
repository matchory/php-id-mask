<?php

declare(strict_types=1);

namespace Matchory\IdMask\Entropy;

use Matchory\IdMask\Exception\NotEnoughEntropyException;

/**
 * Entropy Source
 *
 * Entropy sources generate random bytes.
 *
 * @bundle Matchory\IdMask
 * @internal
 */
interface EntropySourceInterface
{
    /**
     * Generates random bytes of the given length.
     *
     * @param positive-int $length Amount of bytes to generate.
     *
     * @return string Random bytes.
     * @throws NotEnoughEntropyException If the system cannot generate entropy.
     */
    public function generate(int $length): string;
}
