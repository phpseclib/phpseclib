<?php

return (new PhpCsFixer\Config())
    ->setFinder(PhpCsFixer\Finder::create()->in(__DIR__ . '/..'))
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
            // Whitespace
            'array_indentation' => true,
            'blank_line_before_statement' => ['statements' => []],
            'compact_nullable_typehint' => true,
            // TODO: Enable when minimum PHP requirement is >= 7.3
            //'heredoc_indentation' => ['indentation' => 'start_plus_one'],
            'indentation_type' => true,
            'line_ending' => true,
            'method_chaining_indentation' => true,
            // TODO: Try this rule out in its own PR...
            //'no_extra_blank_lines' => ['tokens' => ['break', 'case', 'continue', 'curly_brace_block', 'default', 'extra', 'parenthesis_brace_block', 'return', 'square_brace_block', 'switch', 'throw', 'use', 'use_trait']],
            'no_spaces_around_offset' => ['positions' => ['inside', 'outside']],
            'no_spaces_inside_parenthesis' => true,
            'no_trailing_whitespace' => true,
            'single_blank_line_at_eof' => true,
            'types_spaces' => ['space' => 'none'],
        ]
    );
