<?php

declare(strict_types=1);

namespace phpseclib4\Tests;

use PHPUnit\Framework\TestCase;

class PsalmBaselineTest extends TestCase
{
    public function testErrorTypesAreNotBaselined(): void
    {
        $errorTypes = [
            'UnusedProperty',
            'ParadoxicalCondition',
            'MismatchingDocblockReturnType',
        ];
        $baselineErrorCounts = $this->getBaselineErrorCounts();
        foreach ($errorTypes as $errorType) {
            $this->assertArrayNotHasKey(strtoupper($errorType), $baselineErrorCounts);
        }
    }

    /**
     * @return array<string, int>
     */
    private function getBaselineErrorCounts(): array
    {
        $xmlParser = xml_parser_create('UTF-8');
        $baseline = file_get_contents(__DIR__ . '/../build/psalm_baseline.xml');
        xml_parse_into_struct($xmlParser, $baseline, $values);

        $errorCounts = [];
        /** @var array{level: int, type: string, tag: string, attributes: array{OCCURRENCES?: int}} $element */
        foreach ($values as $element) {
            if ($element['level'] === 3 && ($element['type'] === 'open' || $element['type'] === 'complete')) {
                $errorCounts[$element['tag']] ??= 0;
                $occurrences = $element['attributes']['OCCURRENCES'] ?? 1;
                $errorCounts[$element['tag']] += $occurrences;
            }
        }
        asort($errorCounts);
        return $errorCounts;
    }
}
