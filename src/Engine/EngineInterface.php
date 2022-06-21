<?php

declare(strict_types=1);

namespace Matchory\IdMask\Engine;

use Matchory\IdMask\Exception\DecryptionException;
use Matchory\IdMask\Exception\EncryptionException;
use Matchory\IdMask\Exception\InvalidEngineIdException;
use Matchory\IdMask\Exception\InvalidInputException;
use Matchory\IdMask\Exception\InvalidKeyIdException;
use Matchory\IdMask\Exception\NotEnoughEntropyException;
use Matchory\IdMask\Exception\StateMismatchException;

/**
 * The underlying engine responsible for encrypting the provided id.
 *
 * @bundle Matchory\IdMask
 */
interface EngineInterface
{
    /**
     * Mask (or encrypt) the given ID as bytes. This process is reversible
     * using {@see self::unmask()}.
     *
     * @param int|string $id Plain ID to mask.
     *
     * @return string Masked ID, or cipher text.
     * @throws NotEnoughEntropyException If the system cannot generate enough
     *                                   entropy to generate a verification key.
     * @throws InvalidInputException     If the ID input is unacceptable.
     * @throws InvalidKeyIdException     If the key ID is unacceptable.
     * @throws InvalidEngineIdException  If the engine ID is unacceptable.
     * @throws EncryptionException       If encryption fails.
     */
    public function mask(int|string $id): string;

    /**
     * Unmasks a mask.
     *
     * @param string $mask
     *
     * @return string
     * @throws NotEnoughEntropyException If the system cannot generate enough
     *                                   entropy to generate a verification key.
     * @throws StateMismatchException    If the state of the mask does not match
     *                                   expectations of the system, or data is
     *                                   encountered unexpectedly.
     * @throws DecryptionException       If decryption fails.
     */
    public function unmask(string $mask): string;
}
