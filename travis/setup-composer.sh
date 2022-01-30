#!/bin/sh
composer self-update --no-interaction
composer install --no-interaction
if [ "$TRAVIS_PHP_VERSION" = '8.1.0' ]; then
    composer install --no-interaction --working-dir=build
fi
