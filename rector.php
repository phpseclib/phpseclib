<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

use Rector\Rules\HashLength;
use Rector\Rules\SFTPFilesize;
use Rector\Rules\CreateKey;
use Rector\Rules\PublicKeyLoader;

return RectorConfig::configure()
    ->withPaths([
        // TODO: add project directory path to run rector
        __DIR__ . '/src',
    ])
    ->withRules([
        CreateKey::class,
        SFTPFilesize::class,
        HashLength::class,
        PublicKeyLoader::class,
    ]);
