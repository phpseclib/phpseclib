<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Rules\RemoveClassNamePrefix;


return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->rule(RemoveClassNamePrefix::class);
};
