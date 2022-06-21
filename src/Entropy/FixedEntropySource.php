<?php

declare(strict_types=1);

namespace Matchory\IdMask\Entropy;

/**
 * Fixed Entropy Source
 *
 * Always returns the same entropy data. Only intended for tests.
 *
 * @bundle Matchory\IdMask\Entropy
 * @internal
 */
class FixedEntropySource implements EntropySourceInterface
{
    public function __construct(private readonly string $data)
    {
    }

    /**
     * @inheritDoc
     */
    public function generate(int $length): string
    {
        return $this->data;
    }
}
