#!/bin/sh
set -e
set -x

export PHPSECLIB_SSH_HOSTNAME='localhost'
export PHPSECLIB_SSH_USERNAME='phpseclib'
export PHPSECLIB_SSH_PASSWORD='EePoov8po1aethu2kied1ne0'
export PHPSECLIB_SSH_HOME='/home/phpseclib'

if [ "$TRAVIS_PHP_VERSION" = '5.2' ]
then
  PHPUNIT="phpunit"
else
  PHPUNIT="$(dirname "$0")/../vendor/bin/phpunit"
fi

PHPUNIT_ARGS='--verbose'
if [ `php -r "echo (int) version_compare(PHP_VERSION, '5.4', '<');"` = "1" ]
then
  PHPUNIT_ARGS="$PHPUNIT_ARGS -d zend.enable_gc=0"
fi

if $PHPUNIT --atleast-version 9
then
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/n setUpBeforeClass()/n setUpBeforeClass(): void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/n setUp()/n setUp(): void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/n tearDown()/n tearDown(): void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertIsArray([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertIsString([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertStringContainsString([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/\(n assertStringNotContainsString([^)]*)\)/\1: void/g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/^class Unit_Crypt_\(AES\|Hash\|RSA\)_/class /g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/^class Unit_File_\(X509\)_/class /g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/^class Unit_Math_\(BigInteger\)_/class /g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/^class Unit_\(Crypt\|File\|Math\|Net\)_/class /g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/^class Functional_Net_/class /g'
    find tests -type f -name "*.php" -print0 | xargs -0 sed -i 's/extends Unit_Crypt_Hash_\(SHA512Test\|SHA256Test\)/extends \1/g'
fi

if [ "$TRAVIS_PHP_VERSION" = 'hhvm' -o `php -r "echo (int) version_compare(PHP_VERSION, '7.0', '>=');"` = "1" ]
then
  find tests -type f -name "*Test.php" | \
    parallel --gnu --keep-order \
      "echo '== {} =='; \"$PHPUNIT\" $PHPUNIT_ARGS {};"
else
  "$PHPUNIT" \
    $PHPUNIT_ARGS \
    --coverage-text \
    --coverage-clover code_coverage/clover.xml \
    --coverage-html code_coverage/
fi
