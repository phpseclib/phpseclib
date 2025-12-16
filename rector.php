<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Rules\RemoveClassNamePrefix;
use Rector\Rules\ShortenShaExtends;
use Rector\TypeDeclaration\Rector\ClassMethod\AddReturnTypeDeclarationRector;
use Rector\TypeDeclaration\ValueObject\AddReturnTypeDeclaration;
use PHPStan\Type\VoidType;

return RectorConfig::configure()
    ->withPaths([
        // TODO: add project directory path to run rector
        // __DIR__ . '/tests',
    ])
    ->withRules([
        RemoveClassNamePrefix::class,
        ShortenShaExtends::class
    ])
    ->withConfiguredRule(AddReturnTypeDeclarationRector::class, [
        // PHPUnit lifecycle methods
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'setUp', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'setUpBeforeClass', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'tearDown', new VoidType()),

        // PHPUnit assertion helpers
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertIsArray', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertIsString', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertStringContainsString', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertStringNotContainsString', new VoidType()),
    ]);
