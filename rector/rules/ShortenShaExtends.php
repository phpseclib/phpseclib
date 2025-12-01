<?php

declare(strict_types=1);

namespace Rector\Rules;

use PhpParser\Node;
use Rector\Rector\AbstractRector;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;

// Replaces '~extends Unit_Crypt_Hash_(SHA512Test|SHA256Test)~' => 'extends $1'
final class ShortenShaExtends extends AbstractRector
{
    /**
     * @return array<class-string<Node>>
     */
    public function getNodeTypes(): array
    {
        return [Class_::class];
    }

    public function refactor(Node $node): ?Node
    {
        if (! $node->extends instanceof Name) {
            return null;
        }

        $className = $this->getName($node->extends);
        if ($className === null) {
            return null;
        }

        $pattern = '~^Unit_Crypt_Hash_(SHA512Test|SHA256Test)$~';
        if (preg_match($pattern, $className, $matches)) {
            $node->extends = new Name($matches[1]);
            return $node;
        }

        return null;
    }
}
