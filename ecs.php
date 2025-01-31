<?php

declare(strict_types=1);

use Symplify\EasyCodingStandard\Config\ECSConfig;

return ECSConfig::configure()
    ->withPaths([__DIR__ . '/phpseclib', __DIR__ . '/tests'])
    ->withRootFiles()
    ->withPhpCsFixerSets(perCS20: true)
;
