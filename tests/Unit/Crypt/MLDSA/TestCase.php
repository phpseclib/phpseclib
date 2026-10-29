<?php

/**
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Tests\Unit\Crypt\MLDSA;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Crypt\MLDSA;
use phpseclib4\Tests\PhpseclibTestCase;

abstract class TestCase extends PhpseclibTestCase
{
    /**
     * The NIST ACVP vectors (see extract-acvp-vectors.php)
     */
    private static ?array $vectors = null;

    /**
     * Returns the vectors of a mode (keyGen, sigGen or sigVer) as a data provider array
     *
     * The base64 encoded fields are decoded. $filter, if given, decides which cases are returned.
     */
    protected static function vectors(string $mode, ?callable $filter = null): array
    {
        if (!isset(self::$vectors)) {
            $json = file_get_contents(__DIR__ . '/acvp-ML-DSA-FIPS204.json');
            self::$vectors = json_decode((string) $json, true, 512, JSON_THROW_ON_ERROR);
        }

        $cases = [];
        foreach (self::$vectors[$mode] as $case) {
            foreach (['seed', 'pk', 'sk', 'context', 'message', 'signature'] as $field) {
                if (isset($case[$field])) {
                    $case[$field] = Strings::base64_decode($case[$field]);
                }
            }
            if (isset($filter) && !$filter($case)) {
                continue;
            }
            $cases["$case[parameterSet] tcId $case[tcId]"] = [$case];
        }

        return $cases;
    }

    /**
     * Returns the three parameter sets as a data provider array
     */
    public static function parameterSets(): array
    {
        $sets = [];
        foreach (array_keys(MLDSA::PARAMETER_SETS) as $parameterSet) {
            $sets[$parameterSet] = [$parameterSet];
        }
        return $sets;
    }

    /**
     * Skips the test unless there's an engine that can do ML-DSA
     */
    protected static function requireEngine(): void
    {
        if (!MLDSA::isSupported()) {
            self::markTestSkipped('ML-DSA needs PHP 8.4+ with the OpenSSL extension built against OpenSSL 3.5+');
        }
    }

    /**
     * assertSame() for PEM strings, ignoring the kind of line ending
     */
    public function assertSameNL(string $expected, string $actual, string $message = ''): void
    {
        $expected = str_replace("\r\n", "\n", $expected);
        $actual = str_replace("\r\n", "\n", $actual);
        $this->assertSame($expected, $actual, $message);
    }
}
