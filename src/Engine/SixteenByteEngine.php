<?php

declare(strict_types=1);

namespace Matchory\IdMask\Engine;

use Matchory\IdMask\Entropy\EntropySource;
use Matchory\IdMask\Entropy\EntropySourceInterface;
use Matchory\IdMask\Exception\StateMismatchException;
use Matchory\IdMask\KeyManagement\KeyStore;

use function base64_url_decode;
use function base64_url_encode;
use function hash_hkdf;
use function hash_hmac;
use function rtrim;
use function str_pad;
use function str_slice;
use function substr;

/**
 * Sixteen Byte Engine
 *
 * This schema uses the following cryptographic primitives:
 *  - AES-128 + CBC
 *  - HMAC-SHA256
 *  - HKDF-HMAC-SHA512
 *
 * The basic scheme works as follows.
 * First create the required keys and nonce:
 *
 *
 *     okm = hkdf.expand(key, entropy, 64);
 *     key_s = okm[0-16];
 *     iv_s = okm[16-32];
 *     mac_key_s = okm[32-64];
 *
 *     key ......... provided secret key
 *     entropy ..... 8 byte value. For randomized-ids it is a random value,
 *                   otherwise zero bytes
 *
 * Then encrypt the id:
 *
 *     ciphertext = AES_CBC( iv_s , id ^ entropy)
 *     mac = HMAC(ciphertext)
 *     maskedId_msg= ciphertext | mac[0-8]
 *
 *     id .......... id to mask (aka plaintext)
 *
 * optionally if randomized ids are enabled, also append `entropy` to
 * the output:
 *
 *     maskedId_msg_r = entropy | maskedId_msg
 *
 * Finally, append the version byte (see explanation in 8 byte schema).
 * Use either the randomized or deterministic version:
 *
 *     maskeId_msg_r = obfuscated_version_byte | maskedId_msg_r
 *     maskeId_msg_d = obfuscated_version_byte | maskedId_msg
 */
class SixteenByteEngine extends BaseEngine
{
    public const ENGINE_ID = 1;

    private const ENTROPY_BYTES = 16;

    private const HMAC_ALGORITHM = 'sha256';

    private const MAC_LENGTH_LONG = 16;

    private const  MAC_LENGTH_SHORT = 8;

    /**
     * @param KeyStore               $keyStore         The key store responsible
     *                                                 for providing the secret
     *                                                 keys for the
     *                                                 cryptographic primitives.
     * @param bool                   $randomize        If the masking should
     *                                                 create non-deterministic
     *                                                 IDs (different output for
     *                                                 every call).
     * @param bool                   $highSecurityMode If better security
     *                                                 settings should be used
     *                                                 sacrificing output size
     *                                                 and/or performance.
     * @param EntropySourceInterface $entropySource    The entropy source used
     *                                                 to generate random data.
     */
    public function __construct(
        KeyStore $keyStore,
        bool $randomize = false,
        private readonly bool $highSecurityMode = false,
        EntropySourceInterface $entropySource = new EntropySource()
    ) {
        parent::__construct(
            $keyStore,
            $randomize,
            $entropySource
        );
    }

    /**
     * @inheritDoc
     */
    protected function getCipherAlgorithm(): string
    {
        return 'aes-256-cbc';
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
    public function mask(string|int $id): string
    {
        $this->verifyInput((string)$id);

        $plainId = str_pad(
            (string)$id,
            $this->getSupportedByteLength(),
            "\0"
        );
        $entropy = $this->getEntropy();

        $keys = hash_hkdf(
            self::HMAC_ALGORITHM,
            $this->getCurrentKey()->getKeyBytes(),
            64,
            $entropy,
        );

        // $currentKey = substr($keys, 0, 16);
        $iv = substr($keys, 16, 16);
        $macKey = substr($keys, 32, 32);
        $cipherText = $this->encryptCipherText($plainId ^ $entropy, $iv);

        $version = $this->createVersionByte(
            $this->getCurrentKey(),
            $cipherText
        );

        $mac = substr(str_pad(
            $this->cipherTextMac(
                $macKey,
                $cipherText,
                $iv,
                $version
            ),
            $this->getMacLength(),
            "\0"
        ), 0, $this->getMacLength());

        $mask = $this->randomize()
            ? $version . $entropy . $cipherText . $mac
            : $version . $cipherText . $mac;

        return base64_url_encode($mask);
    }

    /**
     * @inheritDoc
     */
    public function unmask(string $mask): string
    {
        $decodedMask = base64_url_decode($mask);
        [$version, $decodedMask] = str_slice($decodedMask, 1);
        $entropy = $this->getEntropy();

        // Split out the entropy data, if randomization is enabled
        if ($this->randomize()) {
            [$entropy, $decodedMask] = str_slice(
                $decodedMask,
                self::ENTROPY_BYTES
            );
        }

        [$decodedMask, $mac] = str_slice(
            $decodedMask,
            $this->getSupportedByteLength()
        );

        // The MAC should be the last part of the message. By slicing off just
        // as many bytes as we know the MAC is long, we ensure we don't mix it
        // up with any padding bytes.
        [$mac] = str_slice($mac, $this->getMacLength());

        $cipherText = $decodedMask;
        $key = $this->checkAndGetKey($version, $cipherText);

        // Generate HKDF key material from the mask key
        $keys = hash_hkdf(
            self::HMAC_ALGORITHM,
            $key->getKeyBytes(),
            64,
            $entropy,
        );

        // $currentKey = substr($keys, 0, 16);
        $iv = substr($keys, 16, 16);
        $macKey = substr($keys, 32, 32);

        // Recreate th MAC from the cipher text
        $referenceMac = substr($this->cipherTextMac(
            $macKey,
            $cipherText,
            $iv,
            $version
        ), 0, $this->getMacLength());

        // If the MAC does not match, this is likely a forgery attempt
        if ($mac !== $referenceMac) {
            throw new StateMismatchException('MAC does not match');
        }

        $message = $this->decryptCipherText(
            $cipherText,
            $key,
            $iv
        );

        return rtrim($message ^ $entropy, "\0");
    }

    /**
     * Creates a MAC from the cipher text
     *
     * @param string $rawEncryptionKey
     * @param string $cipherText
     * @param string $iv
     * @param string $associatedData
     *
     * @return string
     */
    private function cipherTextMac(
        string $rawEncryptionKey,
        string $cipherText,
        string $iv,
        string $associatedData
    ): string {
        return hash_hmac(
            self::HMAC_ALGORITHM,
            $iv . $cipherText . $associatedData,
            $rawEncryptionKey,
            true,
        );
    }

    private function getMacLength(): int
    {
        return $this->highSecurityMode
            ? self::MAC_LENGTH_LONG
            : self::MAC_LENGTH_SHORT;
    }
}
