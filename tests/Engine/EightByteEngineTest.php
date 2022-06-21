<?php
/** @noinspection SpellCheckingInspection */

declare(strict_types=1);

namespace Matchory\IdMask\Tests\Engine;

use Exception;
use Generator;
use Matchory\IdMask\Engine\EightByteEngine;
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

class EightByteEngineTest extends TestCase
{
    /**
     * Chosen by fair dice roll
     *
     * @var string
     */
    private string $entropySeed = 'b8489e58c1191639';

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
     * @covers       EightByteEngine::mask()
     * @covers       EightByteEngine::unmask()
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
     * @covers EightByteEngine::mask()
     */
    public function testMask(): void
    {
        $id = 'foo';
        $mask = 'gIC6GFLHSFQJDy~3f6_C8SaLivfwUzliqHY~Cz~Owp5L';

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
     * @covers EightByteEngine::mask()
     * @covers EightByteEngine::unmask()
     */
    public function testMaskRandomization(): void
    {
        $actualId = 'foo';
        $expectedMask = '0LhInljBGRY50BWO_NoWOfnG1bWeEwmXVIuK9_BTOWKodj4LP47Cnks-';

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
     * @covers EightByteEngine::unmask()
     */
    public function testUnmask(): void
    {
        $id = 'foo';
        $engine = $this->createEngine();

        self::assertSame($id, $engine->unmask(
            'gIC6GFLHSFQJDy~3f6_C8SaLivfwUzliqHY~Cz~Owp5L'
        ));
    }

    /**
     * @param KeyStore|null $keyStore
     * @param bool          $randomize
     * @param string|null   $entropySeed
     *
     * @return EightByteEngine
     * @throws \InvalidArgumentException
     */
    private function createEngine(
        KeyStore|null $keyStore = null,
        bool $randomize = false,
        string|null $entropySeed = null
    ): EightByteEngine {
        return new EightByteEngine(
            $keyStore ?? $this->createKeyStore(),
            $randomize,
            $this->createEntropySource($entropySeed)
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
            'Mask' => '5~eNy7Q5_DnDwD6FK7I39n6LivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Two characters' => [
            'ID' => 'ab',
            'Mask' => 'XV1r1o3He5JE9sYNI6EHvr6LivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Three characters' => [
            'ID' => 'abc',
            'Mask' => 'aWlpixzChsmzI8g7R1Ok1~KLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Four characters' => [
            'ID' => 'abcd',
            'Mask' => '39909zJLg4kqL9Rl1YUWiAWLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Five characters' => [
            'ID' => 'abcde',
            'Mask' => 'iYn~44gQwk~iqmLPJ57zsmiLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Six characters' => [
            'ID' => 'abcdef',
            'Mask' => '_PwNWQcTma7baWq1UIr7oJuLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Seven characters' => [
            'ID' => 'abcdefg',
            'Mask' => 'qqr7EU8VJuqe2ptCPWkOvK2LivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Eight characters' => [
            'ID' => 'abcdefgh',
            'Mask' => 'GhpsfXi0hEoU7w3LdTcEXRuLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Numeric characters' => [
            'ID' => '12345678',
            'Mask' => '4eE_peUXczgN7TYGplgd7uGLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Special characters' => [
            'ID' => '!"§$%_?',
            'Mask' => '_f1sRn0SZ~7Rv_KxekyKoyOLivfwUzliqHY~Cz~Owp5L',
        ];

        yield 'Only spaces characters' => [
            'ID' => '      ',
            'Mask' => '_f2t7~2eCg0M2zyBZNbPF_CLivfwUzliqHY~Cz~Owp5L',
        ];
    }
}
