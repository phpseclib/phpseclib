<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\TypeDeclaration\Rector\ClassMethod\AddReturnTypeDeclarationRector;
use Rector\TypeDeclaration\ValueObject\AddReturnTypeDeclaration;
use PHPStan\Type\VoidType;

return RectorConfig::configure()
    ->withConfiguredRule(AddReturnTypeDeclarationRector::class, [
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'setUp', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'setUpBeforeClass', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\TestCase', 'tearDown', new VoidType()),

        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertIsArray', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertIsString', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertStringContainsString', new VoidType()),
        new AddReturnTypeDeclaration('PHPUnit\Framework\Assert', 'assertStringNotContainsString', new VoidType()),
    ]);
