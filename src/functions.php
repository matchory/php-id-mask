<?php

declare(strict_types=1);

/**
 * @param string   $string
 * @param int      $offset
 * @param int|null $length
 *
 * @return array{string, string}
 */
function str_slice(string $string, int $offset, int|null $length = null): array
{
    $left = substr($string, 0, $offset);
    $right = substr($string, strlen($left), $length);

    return [$left, $right];
}

function base64_url_encode(string $input): string
{
    return strtr(base64_encode($input), '+/=', '~_-');
}

function base64_url_decode(string $input): string
{
    return base64_decode(strtr($input, '~_-', '+/='));
}

function entropy(string $string): float|int
{
    $buffer = array_fill(0, 256, -1);

    foreach (str_split($string) as $char) {
        $unsigned = 0xff & ord($char);

        if ($buffer[$unsigned] === -1) {
            $buffer[$unsigned] = 0;
        }

        $buffer[$unsigned]++;
    }

    $entropy = 0;

    foreach ($buffer as $count) {
        if ($count === -1) {
            continue;
        }

        $probability = (float)$count / strlen($string);
        $entropy -= $probability * (log($probability) / log(2));
    }

    return $entropy;
}

