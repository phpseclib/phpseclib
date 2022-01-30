#! /usr/bin/env bash
docker run -t --rm -v "$PWD:$PWD" -w $PWD php:$DOCKER_PHP_VERSION-cli php -l -n "$@"
