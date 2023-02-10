<?php

/** @var iterable<SplFileInfo> $files */
$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__));
foreach ($files as $file) {
    if ($file->getExtension() === 'php' && $file->getPathname() !== __FILE__) {
        $fileContents = file_get_contents($file->getPathname());
        if ($fileContents === false) {
            throw new \RuntimeException('file_get_contents() failed: ' . $file->getPathname());
        }
        $patternToReplacementMap = array(
            '~n setUpBeforeClass\(\)~' => 'n setUpBeforeClass(): void',
            '~n setUp\(\)~' => 'n setUp(): void',
            '~n tearDown\(\)~' => 'n tearDown(): void',
            '~(n assertIsArray\([^\)]*\))~' => '$1: void',
            '~(n assertIsString\([^\)]*\))~' => '$1: void',
            '~(n assertStringContainsString\([^\)]*\))~' => '$1: void',
            '~(n assertStringNotContainsString\([^\)]*\))~' => '$1: void',
            '~^class Unit_Crypt_(AES|Hash|RSA)_~m' => 'class ',
            '~^class Unit_File_X509_~m' => 'class ',
            '~^class Unit_Math_BigInteger_~m' => 'class ',
            '~^class Unit_(Crypt|File|Math|Net)_~m' => 'class ',
            '~^class Functional_Net__~m' => 'class ',
            '~extends Unit_Crypt_Hash_(SHA512Test|SHA256Test)~' => 'extends $1'
        );
        $updatedFileContents = preg_replace(
            array_keys($patternToReplacementMap),
            array_values($patternToReplacementMap),
            $fileContents
        );
        if (file_put_contents($file->getPathname(), $updatedFileContents) === false) {
            throw new \RuntimeException('file_put_contents() failed: ' . $file->getPathname());
        }
    }
}
