<?php

declare(strict_types=1);

namespace Matchory\IdMask\Engine;

use Matchory\IdMask\Entropy\EntropySource;
use Matchory\IdMask\Entropy\EntropySourceInterface;
use Matchory\IdMask\Exception\DecryptionException;
use Matchory\IdMask\Exception\EncryptionException;
use Matchory\IdMask\Exception\InvalidEngineIdException;
use Matchory\IdMask\Exception\InvalidInputException;
use Matchory\IdMask\Exception\InvalidKeyIdException;
use Matchory\IdMask\Exception\NotEnoughEntropyException;
use Matchory\IdMask\Exception\StateMismatchException;
use Matchory\IdMask\KeyManagement\KeyStore;
use Matchory\IdMask\KeyManagement\SecretKey;

use function chr;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_error_string;
use function ord;
use function sprintf;
use function str_repeat;
use function strlen;

use const OPENSSL_NO_PADDING;
use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;

/**
 * Base implementation of the engine
 *
 * @bundle Matchory\IdMask
 */
abstract class BaseEngine implements EngineInterface
{
    /**
     * Maximum engine ID. As the engine ID is encoded in 4 bit, the maximum is
     * 0x0F or 15.
     */
    protected final const MAX_ENGINE_ID = 0x0F;

    /**
     * @param KeyStore               $keyStore      The key store responsible
     *                                              for providing the secret
     *                                              keys for the cryptographic
     *                                              primitives.
     * @param bool                   $randomize     If the masking should create
     *                                              non-deterministic IDs
     *                                              (different output for every
     *                                              call).
     * @param EntropySourceInterface $entropySource The entropy source used to
     *                                              generate random data.
     */
    public function __construct(
        private readonly KeyStore $keyStore,
        private readonly bool $randomize = false,
        private readonly EntropySourceInterface $entropySource = new EntropySource()
    ) {
    }

    /**
     * Checks the given version byte for whether it matches the
     * current implementation.
     *
     * This extracts information from the version byte encoded during masking.
     * To see how encoding works, {@see self::createVersionByte()}. To see how
     * decoding the key ID works, {@see self::getKeyIdFromVersion()}. To see how
     * decoding the engine ID works, {@see self::getEngineIdFromVersion()}.
     *
     * @param string $version    Version to decode.
     * @param string $cipherText Used to de-obfuscate the version byte.
     *
     * @return SecretKey Secret key to decode.
     * @throws StateMismatchException If the engine or key IDs don't match.
     */
    protected function checkAndGetKey(
        string $version,
        string $cipherText
    ): SecretKey {
        $versionEngineId = $this->getEngineIdFromVersion(
            $version,
            $cipherText
        );

        if ($versionEngineId !== $this->getEngineId()) {
            throw new StateMismatchException(sprintf(
                'Bad engine ID according to version byte: ' .
                "Expected '%d', got '%d'",
                $this->getEngineId(),
                $versionEngineId
            ));
        }

        $keyId = $this->getKeyIdFromVersion(
            $version,
            $cipherText
        );
        $key = $this->keyStore->getKey($keyId);

        if ($key === null) {
            throw new StateMismatchException(
                "Unknown key ID '{$keyId}'"
            );
        }

        return $key;
    }

    /**
     * Create a version byte.
     *
     * Encodes the key ID and the engine ID into a single byte. As both have
     * 4 bit, or 0-15, available, we can place both in 8 bit by using the
     * following formula:
     * ((<key-id> LEFT-SHIFT 4) OR <engine-id>) XOR <first-cipher-byte>
     *
     * @param SecretKey $key        Secret key to encode in the version byte.
     * @param string    $cipherText Cipher text obfuscate the version byte with.
     *
     * @return string Full version byte, containing key and engine ID.
     * @throws InvalidKeyIdException If the engine ID do not pass length
     *                               validation.
     * @throws InvalidEngineIdException If the engine ID do not pass length
     *                                  validation.
     * @example For a key ID "2" and engine ID "1" and first cipher byte "a":
     *              key id: 2 / 0010
     *              -> left-shift by 4: 0010 0000
     *              engine: 1 / 0001
     *              -> OR engine: 0010 0001
     *              first cipher byte: a / 0110 0001
     *              -> XOR with version+engine: 0100 0000
     *          ...the version byte is 0100 0000.
     *          To reverse the transformation, {@see self::checkAndGetKey()}.
     */
    protected function createVersionByte(
        SecretKey $key,
        string $cipherText
    ): string {
        $keyId = $key->getKeyId();
        $engineId = $this->getEngineId();

        if ($keyId < 0) {
            throw new InvalidKeyIdException(
                'Key ID must be larger than 0'
            );
        }

        if ($keyId > SecretKey::MAX_KEY_ID) {
            throw new InvalidKeyIdException('Key ID too long');
        }

        if ($engineId < 0) {
            throw new InvalidEngineIdException(
                'Engine ID must be larger than 0'
            );
        }

        if ($engineId > self::MAX_ENGINE_ID) {
            throw new InvalidEngineIdException('Engine ID too long');
        }

        // Convert the first character of the cipher text to its byte value
        $cipherByte = ord($cipherText[0]);

        // Store key ID and engine ID in a single byte, and XOR that with the
        // first cipher byte for obfuscation
        return chr((($keyId << 4) | $engineId) ^ $cipherByte);
    }

    /**
     * Decrypts the cipher text.
     *
     * Uses the OpenSSL library to decrypt the encrypted cipher text with the
     * given key as read from the mask and the initialization vector, if given.
     *
     * @param string      $encryptedCipher Encrypted cipher text as read from
     *                                     the mask.
     * @param SecretKey   $key             Secret key to decrypt the cipher.
     * @param string|null $iv              Initialization vector, if required by
     *                                     the selected algorithm.
     *
     * @return string Decrypted cipher text.
     * @throws DecryptionException If decryption fails.
     */
    protected function decryptCipherText(
        string $encryptedCipher,
        SecretKey $key,
        string|null $iv = null
    ): string {
        $cipherText = openssl_decrypt(
            data: $encryptedCipher,
            cipher_algo: $this->getCipherAlgorithm(),
            passphrase: $key->getKeyBytes(),
            options: OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            iv: $iv ?? ''
        );

        if ($cipherText === false) {
            throw DecryptionException::from(openssl_error_string());
        }

        return $cipherText;
    }

    /**
     * Encrypts the cipher text.
     *
     * Uses the OpenSSL library to encrypt the cipher text with the currently
     * active key and the initialization vector, if given.
     *
     * @param string      $cipher  Cipher text to encrypt.
     * @param string|null $iv      Initialization vector data. Only required if
     *                             the selected algorithm requires an IV.
     * @param bool        $padding Whether to enable padding.
     *
     * @return string Encrypted cipher text.
     * @noinspection EncryptionInitializationVectorRandomnessInspection
     * @throws EncryptionException If encryption fails.
     */
    protected function encryptCipherText(
        string $cipher,
        string|null $iv = null,
        bool $padding = false
    ): string {
        $options = OPENSSL_RAW_DATA;

        if ( ! $padding) {
            $options |= OPENSSL_NO_PADDING;
        }

        $encryptedCipher = openssl_encrypt(
            data: $cipher,
            cipher_algo: $this->getCipherAlgorithm(),
            passphrase: $this->getCurrentKey()->getKeyBytes(),
            options: $options,
            iv: $iv ?? ''
        );

        if ($encryptedCipher === false) {
            throw EncryptionException::from(openssl_error_string());
        }

        return $encryptedCipher;
    }

    /**
     * Retrieves the algorithm used to encrypt the cipher text. MUST be a valid
     * algorithm on the target system as returned from {@see hash_algos()}.
     *
     * @return string Algorithm name.
     */
    abstract protected function getCipherAlgorithm(): string;

    /**
     * Retrieves the currently active key from the key manager.
     *
     * @return SecretKey Currently active key instance.
     */
    protected function getCurrentKey(): SecretKey
    {
        return $this->getKeyStore()->getActiveKey();
    }

    /**
     * Retrieves the engine ID.
     *
     * Every implementation or crypto scheme should have its own ID which will
     * be encoded with the version byte. An ID must be checked against the
     * engine ID if it is the correct one.
     *
     * @return int Engine ID as a 4 bit number (0-15).
     */
    abstract protected function getEngineId(): int;

    /**
     * Resolves the engine ID from the version byte.
     *
     * This works by reversing the version transform, that is: We repeat the XOR
     * against the first cipher byte to remove the obfuscation and OR the result
     * with a mask to read the key ID.
     *
     * @param string $version    Version byte content.
     * @param string $cipherText Full cipher text read from the mask.
     *
     * @return int Engine ID.
     */
    protected function getEngineIdFromVersion(
        string $version,
        string $cipherText
    ): int {
        $cipherByte = ord($cipherText[0]);

        return (ord($version) ^ $cipherByte) & 0b0000_1111;
    }

    /**
     * Generates random bytes or returns a null byte string with the configured
     * length for the current engine.
     * This entropy data is used to mask the cipher text. If no randomization is
     * configured, the null byte string works as a no-op.
     *
     * @return string Entropy string or null byte string.
     * @throws NotEnoughEntropyException If the system entropy is too low.
     */
    protected function getEntropy(): string
    {
        $length = $this->getSupportedByteLength();

        return $this->randomize()
            ? $this->entropySource->generate($length)
            : str_repeat("\0", $length);
    }

    /**
     * Resolves the key ID from the version byte.
     *
     * This works by reversing the version transform, that is: We repeat the XOR
     * against the first cipher byte to remove the obfuscation, apply a right
     * shift to remove the engine ID data, and OR the result with a mask to read
     * the key ID.
     *
     * @param string $version    Version byte content.
     * @param string $cipherText Full cipher text read from the mask.
     *
     * @return int Key ID.
     */
    protected function getKeyIdFromVersion(
        string $version,
        string $cipherText
    ): int {
        $cipherByte = ord($cipherText[0]);

        return ((ord($version) ^ $cipherByte) >> 4) & 0b0000_1111;
    }

    /**
     * Retrieves the key manager instance.
     *
     * @return KeyStore Key store instance.
     */
    final protected function getKeyStore(): KeyStore
    {
        return $this->keyStore;
    }

    /**
     * Retrieves the byte length supported by the engine implementation.
     *
     * @return positive-int The amount of supported bytes.
     */
    abstract protected function getSupportedByteLength(): int;

    /**
     * Checks whether mask randomization is enabled.
     *
     * @return bool Whether mask randomization is enabled.
     */
    final protected function randomize(): bool
    {
        return $this->randomize;
    }

    /**
     * Verifies whether the given input data matches the supported byte length.
     *
     * @param string $input Input data given to the engine.
     *
     * @throws InvalidInputException If the ID is too long.
     */
    protected function verifyInput(string $input): void
    {
        $length = strlen($input);

        if ($length === 0) {
            throw new InvalidInputException(
                'ID must contain at least one byte'
            );
        }

        if ($length > $this->getSupportedByteLength()) {
            throw new InvalidInputException(sprintf(
                'ID must be shorter than %d characters',
                $this->getSupportedByteLength()
            ));
        }
    }
}
