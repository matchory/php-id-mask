<?php

declare(strict_types=1);

namespace Matchory\IdMask\KeyManagement;

use InvalidArgumentException;

use function assert;
use function entropy;
use function hex2bin;
use function random_bytes;
use function round;
use function sprintf;
use function str_repeat;
use function strlen;

final class SecretKey
{
    public const MAX_KEY_ID = 0x0F; // 4 bit or 0-15

    private const MAX_KEY_LENGTH_BYTE = 64;

    private const MIN_KEY_ENTROPY = 2.5;

    private const MIN_KEY_LENGTH_BYTE = 12;

    /**
     * Secret key bytes.
     *
     * @var string
     */
    private readonly string $keyBytes;

    /**
     * Secret key ID.
     *
     * @var int
     */
    private readonly int $keyId;

    /**
     * @param int    $keyId    Key ID to use.
     * @param string $keyBytes Raw key bytes.
     *
     * @throws InvalidArgumentException If the key ID or bytes fail validation.
     */
    public function __construct(int $keyId, string $keyBytes)
    {
        if (strlen($keyBytes) < self::MIN_KEY_LENGTH_BYTE) {
            throw new InvalidArgumentException(
                'Key must be at least 8 bytes in length'
            );
        }

        if (strlen($keyBytes) > self::MAX_KEY_LENGTH_BYTE) {
            throw new InvalidArgumentException(
                'Key must be at most 64 bytes in length'
            );
        }

        if ($keyBytes === str_repeat('0', strlen($keyBytes))) {
            throw new InvalidArgumentException(
                'Key must not only contain zeros'
            );
        }

        if (entropy($keyBytes) < self::MIN_KEY_ENTROPY) {
            throw new InvalidArgumentException(
                'Key must have high entropy'
            );
        }

        if ($keyId < 0 || $keyId > self::MAX_KEY_ID) {
            throw new InvalidArgumentException(sprintf(
                'Key ID must be between 0 and %d',
                self::MAX_KEY_ID
            ));
        }

        $this->keyId = $keyId;
        $this->keyBytes = $keyBytes;
    }

    /**
     * Retrieves the secret key byte content.
     *
     * @return string Secret key byte content
     */
    public function getKeyBytes(): string
    {
        return $this->keyBytes;
    }

    /**
     * Retrieves the configured key ID.
     *
     * @return int Key ID.
     */
    public function getKeyId(): int
    {
        return $this->keyId;
    }

    /**
     * Creates a new secret key instance from a secret string.
     *
     * @param string $keyBytes Raw key bytes.
     * @param int    $keyId    Key ID to use. Defaults to 0.
     *
     * @return static New Key instance.
     * @throws InvalidArgumentException If the key fails validation constraints.
     */
    public static function from(string $keyBytes, int $keyId = 0): self
    {
        return new self($keyId, $keyBytes);
    }

    /**
     * Creates a new secret key instance from a secret encoded as a hex string.
     *
     * @param string $keyBytesAsHex Key bytes encoded as a hex string.
     * @param int    $keyId         Key ID to use. Defaults to 0.
     *
     * @return static New Key instance.
     * @throws InvalidArgumentException If the key fails validation constraints.
     */
    public static function fromHex(string $keyBytesAsHex, int $keyId = 0): self
    {
        return new self($keyId, hex2bin($keyBytesAsHex));
    }

    /**
     * Generates a new, random key.
     *
     * @param int $keyId Key ID to use. Defaults to 0.
     *
     * @return static New Key instance.
     * @throws InvalidArgumentException Cannot happen.
     */
    public static function generate(int $keyId = 0): self
    {
        //  Generate a key with average length
        $length = (int)round(
            (self::MIN_KEY_LENGTH_BYTE + self::MAX_KEY_LENGTH_BYTE) / 2
        );

        assert(
            $length > 0,
            'Key length constraints are mutually exclusive'
        );

        return new self($keyId, random_bytes($length));
    }

    /**
     * Checks whether a given key equals another.
     *
     * @param SecretKey|null $key Key to check against.
     *
     * @return bool Whether the keys are equal.
     */
    public function equals(self|null $key): bool
    {
        if ($this === $key) {
            return true;
        }

        if ($key === null) {
            return false;
        }

        return (
            $this->keyId === $key->getKeyId() &&
            $this->getKeyBytes() === $key->getKeyBytes()
        );
    }
}
