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

final class SFTPFilesize extends AbstractRector
{
  private array $sftpVarNames = [];

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
    // Replace use phpseclib\Net\SFTP -> use phpseclib3\Net\SFTP
    if ($node instanceof UseUse) {
      if ($this->isName($node->name, 'phpseclib\Net\SFTP')) {
        $node->name = new Name('phpseclib3\Net\SFTP');
        return $node;
      }
    }

        // Remember the variable name
    if (
        $node instanceof Expression &&
        $node->expr instanceof Assign &&
        $node->expr->var instanceof Variable &&
        $node->expr->expr instanceof New_ &&
        $this->isName($node->expr->expr->class, 'phpseclib\Net\SFTP')
    ) {
        $this->sftpVarNames[$node->expr->var->name] = true;
    }

    if (! $node instanceof MethodCall) {
        return null;
    }

    if(
        ! $node->var instanceof Variable ||
        ! is_string($node->var->name) ||
        ! isset($this->sftpVarNames[$node->var->name])
    ) {
        return null;
    }

    // Replace method call size() -> filesize()
    if ($this->isName($node->name, 'size')) {
      $node->name = new Identifier('filesize');
    }

    return $node;
  }
}