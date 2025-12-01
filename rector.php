<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Rules\AddVoidLifeCycleAssert;
use Rector\Rules\RemoveClassNamePrefix;
use Rector\Rules\ShortenShaExtends;

return RectorConfig::configure()
    ->withPaths([
        // TODO: add project directory path to run rector
        // __DIR__ . '/tests',
    ])
    ->withRules([
        AddVoidLifeCycleAssert::class,
        RemoveClassNamePrefix::class,
        ShortenShaExtends::class
    ]);
