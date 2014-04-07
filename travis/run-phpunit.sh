#!/bin/sh
set -e
set -x

export PHPSECLIB_SSH_HOSTNAME='localhost'
export PHPSECLIB_SSH_USERNAME='phpseclib'
export PHPSECLIB_SSH_PASSWORD='EePoov8po1aethu2kied1ne0'
export PHPSECLIB_SSH_HOME='/home/phpseclib'

phpunit \
  --verbose \
  --coverage-text \
  --coverage-html code_coverage/
