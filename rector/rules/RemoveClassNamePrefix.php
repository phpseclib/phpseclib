<?php

declare(strict_types=1);

namespace Rector\Rules;

use PhpParser\Node;
use Rector\Rector\AbstractRector;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Identifier;

// Replaces:
// '~^class Unit_Crypt_(AES|Hash|RSA)_~m' => 'class ',
// '~^class Unit_File_X509_~m' => 'class ',
// '~^class Unit_Math_BigInteger_~m' => 'class ',
// '~^class Unit_(Crypt|File|Math|Net)_~m' => 'class ',
// '~^class Functional_Net__~m' => 'class ',
final class RemoveClassNamePrefix extends AbstractRector
{
    private const CLASS_PATTERNS = [
        '#^Unit_Crypt_(AES|Hash|RSA)_#',
        '#^Unit_File_X509_#',
        '#^Unit_Math_BigInteger_#',
        '#^Unit_(Crypt|File|Math|Net)_#',
        '#^Functional_Net_#',
    ];

    /**
     * @return array<class-string<Node>>
     */
    public function getNodeTypes(): array
    {
        return [Class_::class];
    }

    public function refactor(Node $node): ?Node
    {
        if (! $node instanceof Class_) {
            return null;
        }

        // do not rename abstract class
        if ($node->isAbstract()) {
            return null;
        }

        $className = $this->getName($node->name);
        if ($className === null) {
            return null;
        }

        $newClassName = $this->removePrefix($className);
        if ($newClassName !== $className) {
            $node->name = new Identifier($newClassName);
            return $node;
        }

        return null;
    }

    private function removePrefix(string $className): string
    {
        foreach (self::CLASS_PATTERNS as $pattern) {
            if (preg_match($pattern, $className)) {
                return preg_replace($pattern, '', $className);
            }
        }
        return $className;
    }
}
