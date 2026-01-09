<?php

declare(strict_types=1);

namespace Rector\Rules;

use Rector\Rector\AbstractRector;

use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\Arg;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\BinaryOp\BitwiseOr;

final class PublicKeyLoader extends AbstractRector
{
    private ?bool $hasExtract = null;
    private ?string $currentFilePath = null;

    private string $rsaVarName = '';
    private $passwordValue = null;
    private $encryptionParam = null;
    private $signatureParam = null;
    private bool $withPaddingInserted = false;

    public function getNodeTypes(): array
    {
        return [
            UseUse::class,
            FuncCall::class,
            Expression::class,
            MethodCall::class
        ];
    }

    private function wrap(Node $node, Node $original): Node
    {
        return $original instanceof Expression ? new Expression($node) : $node;
    }
    // We need to detect the extract call, to conditionally import the right thing
    private function containsExtract(array $nodes): bool
    {
        foreach ($nodes as $node) {
            // Detect extract
            if ($node instanceof Expression && ($node->expr instanceof FuncCall || $node->expr instanceof MethodCall)) {
                $funcName = $node->expr->name;
                if ($funcName instanceof Name && $funcName->toString() === 'extract') {
                    $arg = $node->expr->args[0]->value ?? null;

                    if ($arg instanceof MethodCall && $arg->var instanceof Variable) {
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

    public function refactor(Node $node): null|Node|int
    {
        // Reset per file
        $filePath = $this->file->getFilePath();
        if ($this->currentFilePath !== $filePath) {
            $this->hasExtract = null;
            $this->currentFilePath = $filePath;
        }

        if ($this->hasExtract === null) {
            $this->hasExtract = $this->containsExtract($this->file->getNewStmts());
        }

        // This is a job for createKeyRule then
        if ($this->hasExtract) {
            return null;
        }

        // Replace use phpseclib\Crypt\RSA (incl. alias) -> use phpseclib3\Crypt\PublicKeyLoader
        if ($node instanceof UseUse && $this->isName($node->name, 'phpseclib\Crypt\RSA')) {
            $node->name = new Name('phpseclib3\Crypt\PublicKeyLoader');
            $node->alias = null;
            return $node;
        }

        // Remove $foo = new RSA()
        if ($node instanceof Expression) {
            $expr = $node->expr;

            if ($expr instanceof Assign &&
            $expr->var instanceof Variable &&
            $expr->expr instanceof New_ &&
            $this->isName($expr->expr->class, 'phpseclib\Crypt\RSA')
            ) {
                // Remember the variable name
                $this->rsaVarName = is_string($expr->var->name) ? $expr->var->name : '';
                $this->passwordValue = null;

                return NodeTraverser::REMOVE_NODE;
            }
        }

        $expr = $node;
        if ($node instanceof Expression && $node->expr instanceof MethodCall) {
            $expr = $node->expr;
        }

        if (! $expr instanceof MethodCall) {
            return null;
        }

        if(! ($expr->var instanceof Variable && $expr->var->name === $this->rsaVarName)) {
            return null;
        }

        // Get password value from `setPassword()`
        // And remove $rsa->setPassword('password');
        if ($this->isName($expr->name, 'setPassword')) {
            if (isset($expr->args[0])) {
                $this->passwordValue = $expr->args[0]->value;
            }
            return NodeTraverser::REMOVE_NODE;
        }

        // Match: $rsa->loadKey(...)
        if ($this->isName($expr->name, 'loadKey')) {
            $newArgs = [
                new Arg($expr->args[0]->value),
            ];

            if ($this->passwordValue !== null) {
                $newArgs[] = new Arg($this->passwordValue);
            }

            // $rsa = PublicKeyLoader::load('...', $password);
            $assignExpr = new Assign(
                new Variable($this->rsaVarName),
                new StaticCall(
                    new Name('PublicKeyLoader'),
                    'load',
                    $newArgs
                )
            );

            // If node is a statement wrap it
            return $this->wrap($assignExpr, $node);
        }

        $methodMap = [
            'setHash' => 'withHash',
            'setMGFHash' => 'withMGFHash',
            'setSaltLength' => 'withSaltLength',
            'getSize' => 'getLength',
        ];

        if (isset($methodMap[$expr->name->name])) {
            $newMethod = $methodMap[$expr->name->toString()];
            $expr->name = new Identifier($newMethod);
            // Change the call to be assigned to $rsa
            return $this->wrap(
                new MethodCall(
                    new Variable($this->rsaVarName),
                    $newMethod,
                    $expr->args
                ),
                $node
            );
        }

        if ($this->isName($expr->name, 'setEncryptionMode')) {
            $this->encryptionParam = $expr->args[0]->value;
            if ($this->withPaddingInserted) {
                return NodeTraverser::REMOVE_NODE;
            }

            $this->withPaddingInserted = true;
            return new Expression(
                new MethodCall(
                    new Variable($this->rsaVarName),
                    new Identifier('withPadding')
                )
            );
        }
        if ($this->isName($expr->name, 'setSignatureMode')) {
            $this->signatureParam = $expr->args[0]->value;
            if ($this->withPaddingInserted) {
                return NodeTraverser::REMOVE_NODE;
            }

            $this->withPaddingInserted = true;
            return new Expression(
                new MethodCall(
                    new Variable($this->rsaVarName),
                    new Identifier('withPadding')
                )
            );
        }
        return null;
    }

    private function findWithPaddingMethodCall(array $nodes): ?MethodCall
    {
        foreach ($nodes as $node) {
            if (
                $node instanceof Expression
                && $node->expr instanceof MethodCall
                && $this->isName($node->expr->name, 'withPadding')
            ) {
                return $node->expr;
            }

            // Descend into nested statement lists
            if (property_exists($node, 'stmts') && is_array($node->stmts)) {
                $found = $this->findWithPaddingMethodCall($node->stmts);
                if ($found) {
                    return $found;
                }
            }
        }

        return null;
    }

    public function afterTraverse(array $nodes): ?array
    {
        if (! $this->encryptionParam && ! $this->signatureParam) {
            return null;
        }

        $padding = null;
        if ($this->encryptionParam && $this->signatureParam) {
            $padding = new BitwiseOr($this->signatureParam, $this->encryptionParam);
        } elseif ($this->encryptionParam) {
            $padding = $this->encryptionParam;
        } else {
            $padding = $this->signatureParam;
        }

        $methodCall = $this->findWithPaddingMethodCall($nodes);
        if (! $methodCall instanceof MethodCall) {
            return $nodes;
        }

        $methodCall->args = [
            new Arg($padding),
        ];

        // reset params
        $this->withPaddingInserted = false;
        $this->encryptionParam = null;
        $this->signatureParam = null;
        return $nodes;
    }
}
