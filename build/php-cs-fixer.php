<?php

declare(strict_types=1);

return (new PhpCsFixer\Config())
    ->setFinder(PhpCsFixer\Finder::create()
        ->in(__DIR__ . '/..')
        // https://github.com/phpseclib/phpseclib/pull/2016#discussion_r1691282898
        ->notPath('phpseclib/Crypt/Blowfish.php'))
    ->setCacheFile(__DIR__ . '/php-cs-fixer.cache')
    ->setRiskyAllowed(true)
    // https://github.com/FriendsOfPHP/PHP-CS-Fixer/blob/master/doc/rules/index.rst
    ->setRules(
        [
            // Array
            'array_syntax' => ['syntax' => 'short'],
            // Function Notation
            'native_function_invocation' => ['exclude' => [], 'include' => [], 'scope' => 'all', 'strict' => true],
            // Import
            'fully_qualified_strict_types' => true,
            'global_namespace_import' => ['import_constants' => false, 'import_functions' => false, 'import_classes' => false],
            'no_leading_import_slash' => true,
            'no_unused_imports' => true,
            'ordered_imports' => ['sort_algorithm' => 'alpha', 'imports_order' => ['class', 'const', 'function']],
            'single_import_per_statement' => true,
            'single_line_after_imports' => true,
            // PHPDoc
            'no_superfluous_phpdoc_tags' => true,
            'phpdoc_trim_consecutive_blank_line_separation' => true,
            'phpdoc_trim' => true,

            '@PHP81Migration' => true,
            '@PHP80Migration:risky' => true,
        ]
    );
