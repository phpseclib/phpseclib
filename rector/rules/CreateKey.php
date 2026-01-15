<?php

declare(strict_types=1);

namespace Rector\Rules;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\NodeTraverser;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Cast\String_;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\Expression;

use Rector\Rector\AbstractRector;

final class CreateKey extends AbstractRector
{
  private ?bool $hasExtract = null;
  private ?string $currentFilePath = null;
  private array $rsaVarsUsedInExtract = [];

  public function getNodeTypes(): array
  {
    return [
      UseUse::class,
      Expression::class,
    ];
  }

  // We only continue when there is an extract(->createKey())
  private function containsExtract(array $nodes): bool
  {
      foreach ($nodes as $node) {
        if ($node instanceof Expression && ($node->expr instanceof FuncCall || $node->expr instanceof MethodCall)) {
            $funcName = $node->expr->name;
            if ($funcName instanceof Name && $funcName->toString() === 'extract') {
                $arg = $node->expr->args[0]->value ?? null;

                if (
                  $arg instanceof MethodCall &&
                  $this->isName($arg->name, 'createKey') &&
                  $arg->var instanceof Variable
                ) {
                  return true;
                }
            }
        }

        // Recurse into class/method bodies
        if (property_exists($node, 'stmts') && is_array($node->stmts)) {
            if ($this->containsExtract($node->stmts)) {
                return true;
            }
        }
      }
      return false;
  }

  public function refactor(Node $node): null|Node|int|array
  {
    $filePath = $this->file->getFilePath();
    if ($this->currentFilePath !== $filePath) {
        $this->hasExtract = null;
        $this->currentFilePath = $filePath;
    }

    if ($this->hasExtract === null) {
      $this->hasExtract = $this->containsExtract($this->file->getNewStmts());
    }

    // This is a job for PublicKeyLoaderRule
    if (! $this->hasExtract) {
        return null;
    }

    // Detect extract($rsa->createKey(...))
    if (
      $node instanceof Expression &&
      $node->expr instanceof FuncCall &&
      $this->isName($node->expr->name, 'extract')
    ) {
      $arg = $node->expr->args[0]->value ?? null;
      if (
        $arg instanceof MethodCall &&
        $this->isName($arg->name, 'createKey') &&
        $arg->var instanceof Variable &&
        is_string($arg->var->name)
      ) {
        $this->rsaVarsUsedInExtract[$arg->var->name] = true;
      }
    }

    // Replace use phpseclib\Crypt\RSA -> use phpseclib3\Crypt\RSA
    if ($node instanceof UseUse) {
      if ($this->isName($node->name, 'phpseclib\Crypt\RSA')) {
        $node->name = new Name('phpseclib3\Crypt\RSA');
        $node->alias = null;
        return $node;
      }
    }

    if (! $node instanceof Expression) {
      return null;
    }
    $expr = $node->expr;

    // Remove new RSA() assignment
    if ($expr instanceof Assign &&
    $expr->var instanceof Variable &&
    $expr->expr instanceof New_ &&
    $this->isName($node->expr->expr->class, 'phpseclib\Crypt\RSA')
    ) {
      $varName = is_string($expr->var->name) ? $expr->var->name : null;
      // new RSA() is removed only when it is used in extract()
      if ($varName !== null && isset($this->rsaVarsUsedInExtract[$varName])) {
        return NodeTraverser::REMOVE_NODE;
      }
    }

    // Match: extract(...)
    if (! $expr instanceof FuncCall) {
      return null;
    }
    if (! $this->isName($expr->name, 'extract')) {
      return null;
    }
    // extract() must have arguments
    if (! isset($expr->args[0])) {
      return null;
    }
    // Argument must be a method -> $rsa->createKey(...)
    $arg = $expr->args[0]->value;
    if (! ($arg instanceof MethodCall) || ! ($this->isName($arg->name, 'createKey'))) {
      return null;
    }

    // Extract variable name from: $rsa->createKey(...)
    $varName = $arg->var instanceof Variable ? $arg->var->name : null;
    if (
      ! is_string($varName) ||
      ! isset($this->rsaVarsUsedInExtract[$varName])
    ) {
      return null;
    }

    // refactor to $rsa = RSA::createKey(2048);
    $originalPrivateKeyExpr = new Expression(
      new Assign(
        // or $varName if you want to keep the original one
        new Variable('privateKey'),
        new StaticCall(
          new Name('RSA'),
          'createKey',
          $arg->args
        )
      )
    );

    // $publickey = $privatekey->getPublicKey();
    $publicKeyExpr = new Expression(
      new Assign(
        new Variable('publicKey'),
        new MethodCall(
          new Variable('privateKey'),
          'getPublicKey',
        )
      )
    );

    // $privatekey = (string) $privatekey;
    $privateKeyString = new Expression(
      new Assign(
        new Variable('privateKey'),
        new String_(
          new Variable('privateKey'),
        )
      )
    );
    // $publickey = (string) $publickey;
    $publicKeySting = new Expression(
      new Assign(
        new Variable('publicKey'),
        new String_(
          new Variable('publicKey'),
        )
      )
    );

    return [
      $originalPrivateKeyExpr,
      $publicKeyExpr,
      $privateKeyString,
      $publicKeySting,
    ];
  }
}
