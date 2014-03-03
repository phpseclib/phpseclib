#!/bin/sh
set -e
set -x

phpunit \
  --verbose \
  --coverage-text \
  --coverage-html code_coverage/
