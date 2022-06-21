<?php
/** @noinspection SpellCheckingInspection */

declare(strict_types=1);

namespace Matchory\IdMask\Tests\Engine;

use Exception;
use Generator;
use Matchory\IdMask\Engine\SixteenByteEngine;
use Matchory\IdMask\Entropy\EntropySourceInterface;
use Matchory\IdMask\Entropy\FixedEntropySource;
use Matchory\IdMask\KeyManagement\KeyStore;
use Matchory\IdMask\KeyManagement\SecretKey;
use PHPUnit\Framework\ExpectationFailedException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SebastianBergmann\RecursionContext\InvalidArgumentException;

use function hex2bin;
use function in_array;
use function random_bytes;

class SixteenByteEngineTest extends TestCase
{
    /**
     * Chosen by fair dice roll
     *
     * @var string
     */
    private string $entropySeed = '6b61e68361ed28828b495dbf50a9f679';

    private string $key = '9d5100cebffa729aaffecd3ad25dc5aeea4f13bb';

    /**
     * @throws RuntimeException
     * @throws \InvalidArgumentException
     * @throws Exception
     */
    public function testCollisions(): void
    {
        $this->markTestSkipped('Enable collision testing manually: It takes a while');

        /** @noinspection PhpUnreachableStatementInspection */
        $engine = $this->createEngine();
        $seen = [];

        for ($i = 0; $i < 100_000; $i++) {
            $mask = $engine->mask(random_bytes(8));

            if (in_array($mask, $seen, false)) {
                throw new RuntimeException(
                    "Collision after {$i} random masks"
                );
            }

            $seen[] = $mask;
        }

        $this->expectNotToPerformAssertions();
    }

    /**
     * @dataProvider ids
     *
     * @param string $id
     * @param string $mask
     *
     * @throws ExpectationFailedException
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @throws \InvalidArgumentException
     * @covers       SixteenByteEngine::mask()
     * @covers       SixteenByteEngine::unmask()
     */
    public function testCombinations(string $id, string $mask): void
    {
        $engine = $this->createEngine();
        $actualMask = $engine->mask($id);
        $actualId = $engine->unmask($actualMask);

        self::assertSame($mask, $actualMask);
        self::assertSame($id, $actualId);
    }

    /**
     * @throws \InvalidArgumentException
     * @throws ExpectationFailedException
     * @throws RuntimeException
     * @throws InvalidArgumentException
     * @covers SixteenByteEngine::mask()
     */
    public function testMask(): void
    {
        $id = 'foo';
        $mask = 'eHnYT18H4QjezLa40ol~wyiXq1FNKf79hA--';

        $engine = $this->createEngine();

        self::assertSame(
            $mask,
            $engine->mask($id)
        );
    }

    /**
     * @throws \InvalidArgumentException
     * @throws ExpectationFailedException
     * @throws RuntimeException
     * @throws InvalidArgumentException
     * @covers SixteenByteEngine::mask()
     * @covers SixteenByteEngine::unmask()
     */
    public function testMaskRandomization(): void
    {
        $actualId = 'foo';
        $expectedMask = 'Zmth5oNh7SiCi0ldv1Cp9nln7g_RJPvL_fgCKAf_w0Hp00C1HUvFjIU-';

        $engine = $this->createEngine(randomize: true);
        $mask = $engine->mask($actualId);

        self::assertSame($expectedMask, $mask);
        self::assertSame($actualId, $engine->unmask($mask));
    }

    /**
     * @throws ExpectationFailedException
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @throws \InvalidArgumentException
     * @covers SixteenByteEngine::unmask()
     */
    public function testUnmask(): void
    {
        $id = 'foo';
        $engine = $this->createEngine();

        self::assertSame($id, $engine->unmask(
            'eHnYT18H4QjezLa40ol~wyiXq1FNKf79hA--'
        ));
    }

    /**
     * @param KeyStore|null $keyStore
     * @param bool          $randomize
     * @param string|null   $entropySeed
     *
     * @return SixteenByteEngine
     * @throws \InvalidArgumentException
     */
    private function createEngine(
        KeyStore|null $keyStore = null,
        bool $randomize = false,
        string|null $entropySeed = null
    ): SixteenByteEngine {
        return new SixteenByteEngine(
            $keyStore ?? $this->createKeyStore(),
            $randomize,
            entropySource: $this->createEntropySource($entropySeed)
        );
    }

    private function createEntropySource(
        string|null $entropySeedHex = null
    ): EntropySourceInterface {
        $entropySeed = hex2bin($entropySeedHex ?? $this->entropySeed);

        return new FixedEntropySource($entropySeed);
    }

    /**
     * @param string|null $key
     *
     * @return KeyStore
     * @throws \InvalidArgumentException
     */
    private function createKeyStore(string|null $key = null): KeyStore
    {
        return KeyStore::with(SecretKey::fromHex(
            $key ?? $this->key
        ));
    }

    private function ids(): Generator
    {
        yield 'Single character' => [
            'ID' => 'a',
            'Mask' => 'S0q6AJ3K0r5ZRh7vJDhwGXtRda~MqwcPGw--',
        ];

        yield 'Two characters' => [
            'ID' => 'ab',
            'Mask' => 'BgdD310vMKio_RKkQDbenJy5T7d9uXoW_g--',
        ];

        yield 'Three characters' => [
            'ID' => 'abc',
            'Mask' => 'ERC6_c9w_z4StGMyTLqcS8Rz1jHraeCkFQ--',
        ];

        yield 'Four characters' => [
            'ID' => 'abcd',
            'Mask' => 'BQRTt8oPbncRZ9j0KjpoAgjjxF2NSSW~~w--',
        ];

        yield 'Five characters' => [
            'ID' => 'abcde',
            'Mask' => 'YmM3h_iLuA_02MxSKeg56jKu81Wsttw~Yw--',
        ];

        yield 'Six characters' => [
            'ID' => 'abcdef',
            'Mask' => 'oaCn45FtoR~7M0wyXKvgz6Puwx0RwWW1GQ--',
        ];

        yield 'Seven characters' => [
            'ID' => 'abcdefg',
            'Mask' => 'MTBv9I5dzqG7FeHb~USjn6BvTqA8O67BlA--',
        ];

        yield 'Sixteen characters' => [
            'ID' => 'abcdefgh',
            'Mask' => 'x8bkGkzzcfKfPLouUlgcfyRj~bWmoBc7qw--',
        ];

        yield 'Numeric characters' => [
            'ID' => '12345678',
            'Mask' => 'x8aGsTXAozEAWWZSmkrWjlFzlNRhT4f48A--',
        ];

        yield 'Special characters' => [
            'ID' => '!"§$%_?',
            'Mask' => '9_awvt3rZshWiCDXucLdzdegQr2xdaRKNw--',
        ];

        yield 'Only spaces characters' => [
            'ID' => '       ',
            'Mask' => 'FRRaSf9Hp66IjXhD4vRh1904SQaijDtEUw--',
        ];
    }
}
