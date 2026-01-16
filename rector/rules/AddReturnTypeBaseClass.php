<?php

declare(strict_types=1);

namespace Rector\Rules;

use PhpParser\Node;
use Rector\Rector\AbstractRector;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Identifier;

// Replaces:
// '~n setUpBeforeClass\(\)~' => 'n setUpBeforeClass(): void',
// '~n setUp\(\)~' => 'n setUp(): void',
// '~n tearDown\(\)~' => 'n tearDown(): void',
// '~(n assertIsArray\([^\)]*\))~' => '$1: void',
// '~(n assertIsString\([^\)]*\))~' => '$1: void',
// '~(n assertStringContainsString\([^\)]*\))~' => '$1: void',
// '~(n assertStringNotContainsString\([^\)]*\))~' => '$1: void',
final class AddReturnTypeBaseClass extends AbstractRector
{
    private const LIFECYCLE_METHODS = [
        'setUp',
        'setUpBeforeClass',
        'tearDown'
    ];

    private const ASSERT_METHODS = [
        'assertIsArray',
        'assertIsString',
        'assertStringContainsString',
        'assertStringNotContainsString'
    ];

    /**
     * @return array<class-string<Node>>
     */
    public function getNodeTypes(): array
    {
        return [ClassMethod::class];
    }

    public function refactor(Node $node): ?Node
    {
        if (! $node instanceof ClassMethod) {
            return null;
        }

        $methodName = $this->getName($node->name);
        if (! $methodName) {
            return null;
        }

        if (
          (in_array($methodName, self::LIFECYCLE_METHODS, true)) ||
          (in_array($methodName, self::ASSERT_METHODS, true))
        ) {
            $node->returnType = new Identifier('void');
            return $node;
        }

        return null;
    }
}
