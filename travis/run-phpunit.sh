#!/bin/sh
set -e
set -x

export PHPSECLIB_SSH_HOSTNAME='localhost'
export PHPSECLIB_SSH_USERNAME='phpseclib'
export PHPSECLIB_SSH_PASSWORD='EePoov8po1aethu2kied1ne0'
export PHPSECLIB_SSH_HOME='/home/phpseclib'

PHPUNIT_EXTRA_ARGS=''
if [ "$TRAVIS_PHP_VERSION" = '5.3.3' ]
then
  PHPUNIT_EXTRA_ARGS="$PHPUNIT_EXTRA_ARGS -d zend.enable_gc=0"
fi

phpunit \
  $PHPUNIT_EXTRA_ARGS \
  --verbose \
  --coverage-text \
  --coverage-html code_coverage/
