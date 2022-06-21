<?php

declare(strict_types=1);

namespace Matchory\IdMask\KeyManagement;

use InvalidArgumentException;

use function array_key_exists;
use function count;

class KeyStore
{
    /**
     * Holds the currently active key ID.
     *
     * @var int
     */
    private readonly int $activeKeyId;

    /**
     * Holds all known keys.
     *
     * Holds a dictionary of key IDs to keys.
     *
     * @var array<int, SecretKey>
     */
    private array $keys = [];

    /**
     * @param SecretKey $activeKey
     * @param SecretKey ...$moreKeys
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        SecretKey $activeKey,
        SecretKey ...$moreKeys
    ) {
        $this->activeKeyId = $activeKey->getKeyId();

        $keys = [$activeKey, ...$moreKeys];

        foreach ($keys as $key) {
            $id = $key->getKeyId();

            if (array_key_exists($id, $this->keys)) {
                throw new InvalidArgumentException(
                    "Key with ID {$id} was already added"
                );
            }

            $this->keys[$id] = $key;
        }
    }

    /**
     * Retrieves the currently active key.
     *
     * @return SecretKey Key instance.
     */
    public function getActiveKey(): SecretKey
    {
        return $this->keys[$this->getActiveKeyId()];
    }

    /**
     * Retrieves the currently active key ID.
     *
     * @return int Key ID.
     */
    public function getActiveKeyId(): int
    {
        return $this->activeKeyId;
    }

    public function getKey(int $id): SecretKey|null
    {
        return $this->keys[$id];
    }

    /**
     * Creates a new key store with the given key.
     *
     * @param SecretKey $key
     *
     * @return self
     * @throws InvalidArgumentException
     */
    public static function with(SecretKey $key): self
    {
        return new self($key);
    }

    /**
     * Clears the key storage
     */
    public function clear(): void
    {
        $this->keys = [];
    }

    /**
     * Retrieves the amount of keys in the key manager.
     *
     * @return int Amount of keys.
     */
    public function size(): int
    {
        return count($this->keys);
    }
}
