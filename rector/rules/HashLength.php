<?php

declare(strict_types=1);

namespace Rector\Rules;
use Rector\Rector\AbstractRector;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\Expression;

final class HashLength extends AbstractRector
{
  private array $hashVarNames = [];

  public function getNodeTypes(): array
  {
    return [
      UseUse::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  public function refactor(Node $node): ?Node
  {
    // Replace use phpseclib\Crypt\Hash -> use phpseclib3\Crypt\Hash
    if ($node instanceof UseUse) {
      if ($this->isName($node->name, 'phpseclib\Crypt\Hash')) {
        $node->name = new Name('phpseclib3\Crypt\Hash');
      }
    }

    // Remember the variable name
    if (
        $node instanceof Expression &&
        $node->expr instanceof Assign &&
        $node->expr->var instanceof Variable &&
        $node->expr->expr instanceof New_ &&
        $this->isName($node->expr->expr->class, 'phpseclib\Crypt\Hash')
    ) {
        $this->hashVarNames[$node->expr->var->name] = true;
    }

    if (! $node instanceof MethodCall) {
        return null;
    }
    if(
        ! $node->var instanceof Variable ||
        ! is_string($node->var->name) ||
        ! isset($this->hashVarNames[$node->var->name])
    ) {
        return null;
    }

    // Replace method call getLength() -> getLengthInBytes()
    if ($this->isName($node->name, 'getLength')) {
      $node->name = new Identifier('getLengthInBytes');
    }

    return $node;
  }
}