<?php

/**
 * Extracts the ML-DSA test vectors used by the unit tests from the NIST ACVP files
 *
 * The full ACVP files are too big to ship (about 25 MB), so this script keeps a small subset
 * and writes it to acvp-ML-DSA-FIPS204.json, next to this script. The source commit and the
 * SHA-256 of each input file are recorded in the output so that the extraction can be checked.
 * Values are base64 encoded (the ACVP files use hex) to keep the file small.
 *
 * Usage:
 *
 *   php extract-acvp-vectors.php <directory with the ACVP json files> <ACVP-Server commit>
 *
 * The directory needs the prompt.json, expectedResults.json and internalProjection.json files of
 * gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204 from https://github.com/usnistgov/ACVP-Server
 * named ML-DSA-<mode>-FIPS204.<kind>.json
 *
 * What's kept:
 *
 * - keyGen: the first 5 cases of each parameter set (seed and pk; sk for the first case only)
 * - sigGen: for each parameter set, the deterministic external / pure case with an empty context
 *   that has the shortest message (verifiable with the OpenSSL engine) and the deterministic
 *   external / pure case with a context that has the shortest message (needs a pure-PHP engine)
 * - sigVer: every external / pure case with an empty context (3, all with invalid signatures) plus,
 *   for each parameter set, the valid case with a context and the preHash case that have the
 *   shortest messages (both need a pure-PHP engine)
 *
 * @author    Adriel Cavalcante
 * @copyright 2026 Adriel Cavalcante
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

if ($argc != 3) {
    fwrite(STDERR, "Usage: php extract-acvp-vectors.php <directory with the ACVP json files> <ACVP-Server commit>\n");
    exit(1);
}

$dir = rtrim($argv[1], '/\\');
$commit = $argv[2];

$read = function (string $mode, string $kind) use ($dir): array {
    $file = "$dir/ML-DSA-$mode-FIPS204.$kind.json";
    $json = file_get_contents($file);
    if ($json === false) {
        fwrite(STDERR, "Unable to read $file\n");
        exit(1);
    }
    return [json_decode($json, true, 512, JSON_THROW_ON_ERROR), hash('sha256', $json)];
};

$files = [];
$vectors = [];
foreach (['keyGen', 'sigGen', 'sigVer'] as $mode) {
    foreach (['prompt', 'expectedResults', 'internalProjection'] as $kind) {
        [$data, $hash] = $read($mode, $kind);
        $files["ML-DSA-$mode-FIPS204.$kind.json"] = $hash;
        $vectors[$mode][$kind] = $data;
    }
}

// indexes the tests of every group by tcId so that prompt, expectedResults and internalProjection can be joined
$index = function (array $data): array {
    $tests = [];
    foreach ($data['testGroups'] as $group) {
        foreach ($group['tests'] as $test) {
            $tests[$test['tcId']] = $test;
        }
    }
    return $tests;
};

$b64 = fn (string $hex): string => base64_encode(hex2bin($hex));

$output = [
    'source' => [
        'repository' => 'https://github.com/usnistgov/ACVP-Server',
        'commit' => $commit,
        'path' => 'gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204',
        'vsId' => $vectors['keyGen']['prompt']['vsId'],
        'sha256' => $files,
        'script' => 'tests/Unit/Crypt/MLDSA/extract-acvp-vectors.php',
        'encoding' => 'base64 (the ACVP files use hex)',
    ],
    'keyGen' => [],
    'sigGen' => [],
    'sigVer' => [],
];

$expected = $index($vectors['keyGen']['expectedResults']);
foreach ($vectors['keyGen']['prompt']['testGroups'] as $group) {
    foreach (array_slice($group['tests'], 0, 5) as $i => $test) {
        $case = [
            'parameterSet' => $group['parameterSet'],
            'tcId' => $test['tcId'],
            'seed' => $b64($test['seed']),
            'pk' => $b64($expected[$test['tcId']]['pk']),
        ];
        if ($i == 0) {
            $case['sk'] = $b64($expected[$test['tcId']]['sk']);
        }
        $output['keyGen'][] = $case;
    }
}

$expected = $index($vectors['sigGen']['expectedResults']);
$noContext = [];
$withContext = [];
foreach ($vectors['sigGen']['prompt']['testGroups'] as $group) {
    if ($group['signatureInterface'] != 'external' || $group['preHash'] != 'pure' || !$group['deterministic']) {
        continue;
    }
    foreach ($group['tests'] as $test) {
        $case = [
            'parameterSet' => $group['parameterSet'],
            'tcId' => $test['tcId'],
            'deterministic' => $group['deterministic'],
            'preHash' => $group['preHash'],
            'context' => $b64($test['context']),
            'sk' => $b64($test['sk']),
            'message' => $b64($test['message']),
            'signature' => $b64($expected[$test['tcId']]['signature']),
            // what the OpenSSL engine can do: verify the signature of a pure case with an empty context
            'opensslTestable' => $test['context'] == '',
        ];
        $bucket = $case['opensslTestable'] ? 'noContext' : 'withContext';
        $current = $$bucket[$group['parameterSet']] ?? null;
        if (!isset($current) || strlen($case['message']) < strlen($current['message'])) {
            $$bucket[$group['parameterSet']] = $case;
        }
    }
}
foreach ([$noContext, $withContext] as $cases) {
    foreach ($cases as $case) {
        $output['sigGen'][] = $case;
    }
}

$expected = $index($vectors['sigVer']['expectedResults']);
$projection = $index($vectors['sigVer']['internalProjection']);
$withContext = [];
$preHash = [];
foreach ($vectors['sigVer']['prompt']['testGroups'] as $group) {
    if ($group['signatureInterface'] != 'external') {
        continue;
    }
    foreach ($group['tests'] as $test) {
        $case = [
            'parameterSet' => $group['parameterSet'],
            'tcId' => $test['tcId'],
            'preHash' => $group['preHash'],
            'hashAlg' => $test['hashAlg'] ?? null,
            'context' => $b64($test['context']),
            'pk' => $b64($test['pk']),
            'message' => $b64($test['message']),
            'signature' => $b64($test['signature']),
            'testPassed' => $expected[$test['tcId']]['testPassed'],
            'reason' => $projection[$test['tcId']]['reason'] ?? null,
            'opensslTestable' => $group['preHash'] == 'pure' && $test['context'] == '',
        ];
        if ($case['opensslTestable']) {
            $output['sigVer'][] = $case;
            continue;
        }
        if ($group['preHash'] == 'pure' && !$case['testPassed']) {
            continue;
        }
        $bucket = $group['preHash'] == 'pure' ? 'withContext' : 'preHash';
        $current = $$bucket[$group['parameterSet']] ?? null;
        if (!isset($current) || strlen($case['message']) < strlen($current['message'])) {
            $$bucket[$group['parameterSet']] = $case;
        }
    }
}
foreach ([$withContext, $preHash] as $cases) {
    foreach ($cases as $case) {
        $output['sigVer'][] = $case;
    }
}

$file = __DIR__ . '/acvp-ML-DSA-FIPS204.json';
$json = json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
file_put_contents($file, $json);

printf(
    "%s: %d keyGen, %d sigGen and %d sigVer cases, %d bytes\n",
    basename($file),
    count($output['keyGen']),
    count($output['sigGen']),
    count($output['sigVer']),
    strlen($json)
);
