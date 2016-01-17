#!/bin/sh
if [ "$TRAVIS_PHP_VERSION" == "5.3.3" ]
then
    # openssl is disabled on travis ci on 5.3.3:
    # https://docs.travis-ci.com/user/languages/php#PHP-installation
    composer self-update --no-interaction --disable-tls
else
    composer self-update --no-interaction
fi
composer install --no-interaction