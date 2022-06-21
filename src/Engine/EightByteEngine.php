<?php

declare(strict_types=1);

namespace Matchory\IdMask\Engine;

use Matchory\IdMask\Exception\StateMismatchException;

use function base64_url_decode;
use function base64_url_encode;
use function rtrim;
use function str_pad;
use function str_slice;

/**
 * Eight byte engine
 *
 * This schema uses the following cryptographic primitives:
 *  - AES-128 + ECB + No Padding
 *
 * Using a full 16 byte AES block, we create a message containing of the 8 byte
 * ID (i.e. the plaintext) and an 8 byte reference value. Then we encrypt it
 * with AES/ECB (since we encrypt only a single block, a block mode using an IV
 * like CBC wouldn't make a difference):
 *
 *     message_d = ( refValue_1a | id )
 *     maskedId_d = ciphertext_d = AES_ECB( message_d )
 *
 * When decrypting, we compare the reference value, and if it has changed we
 * discard the id, since either the key is incorrect, or this was a
 * forgery attempt:
 *
 *     AES_ECB( maskedId_d ) = refValue_1b | id
 *     refValue_1a == refValue_1b
 *
 * Deterministic
 * -------------
 * In the deterministic mode the reference value is just a 8 byte long array
 * of zeros.
 *
 * Randomized
 * ----------
 * In the randomized mode the reference value is a random 8 byte long array.
 * Because the decryption requires knowledge of this value it will be prepended
 * to the cipher text:
 *
 *     ciphertext_r = AES_ECB( refValue_rnd | id )
 *     maskedId_r = refValue_rnd | ciphertext_r
 *
 * Version Byte
 * ------------
 * Both modes have a version byte prepended which will be xor-ed with the first
 * byte of the cipher text for simple obfuscation:
 *
 *     obfuscated_version_byte = version_byte ^ ciphertext[0]
 *
 * Finally, the message looks like this:
 *
 *     maskeId_msg_d = obfuscated_version_byte | maskedId_d
 *
 * and
 *
 *     maskeId_msg_r = obfuscated_version_byte | maskedId_r
 *
 * for randomized encryption.
 */
class EightByteEngine extends BaseEngine
{
    private const ENGINE_ID = 0;

    private const ENTROPY_BYTES = 8;

    /**
     * @inheritDoc
     */
    protected function getCipherAlgorithm(): string
    {
        return 'aes-256-ecb';
    }

    /**
     * @inheritDoc
     */
    protected function getEngineId(): int
    {
        return self::ENGINE_ID;
    }

    /**
     * @inheritDoc
     */
    protected function getSupportedByteLength(): int
    {
        return self::ENTROPY_BYTES;
    }

    /**
     * @inheritDoc
     */
    public function mask(int|string $id): string
    {
        $this->verifyInput((string)$id);

        $plainId = str_pad(
            (string)$id,
            $this->getSupportedByteLength(),
            "\0"
        );
        $entropy = $this->getEntropy();
        $message = $entropy . $plainId;
        $key = $this->getCurrentKey();
        $cipherText = $this->encryptCipherText($message, padding: true);
        $version = $this->createVersionByte($key, $cipherText);
        $mask = $this->randomize()
            ? $version . $entropy . $cipherText
            : $version . $cipherText;

        return base64_url_encode($mask);
    }

    /**
     * @inheritDoc
     */
    public function unmask(string $mask): string
    {
        $decodedMask = base64_url_decode($mask);
        [$version, $decodedMask] = str_slice($decodedMask, 1);
        $entropyData = $this->getEntropy();

        if ($this->randomize()) {
            [$entropyData, $decodedMask] = str_slice(
                $decodedMask,
                self::ENTROPY_BYTES
            );
        }

        $cipherText = $decodedMask;

        // Extract the key ID and check the engine version
        $key = $this->checkAndGetKey(
            $version,
            $cipherText
        );

        // Decrypt the cipher text itself
        $message = $this->decryptCipherText($cipherText, $key);

        // The message is composed of the entropy and the payload
        [$actualEntropy, $message] = str_slice(
            $message,
            self::ENTROPY_BYTES
        );

        if ($actualEntropy !== $entropyData) {
            throw new StateMismatchException(
                'Internal reference entropy does not match, probably ' .
                'forgery attempt or incorrect key'
            );
        }

        // By taking only the maximum amount of bytes available, we remove some
        // padding bytes from the output
        [$id] = str_slice(
            $message,
            $this->getSupportedByteLength()
        );

        // Remove padding null bytes from the end of the ID
        return rtrim($id, "\0");
    }
}
