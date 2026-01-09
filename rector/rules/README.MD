# Rector

phpseclib uses [Rector](https://getrector.com/) that you can run on any PHP project to get an instant upgrade or automated refactoring.

## Rector file structure

Rector works with `rector.php` config file. This is located at the project root and this is where you define the project path and rules to be implemented.

This is current file structure for rector rules and tests:

```
/rector
    /rules
        CustomRuleName.php
/tests
    /Rector
        /CustomRuleName
            /Fixture
                test_fixture.php.inc
                skip_rule_test_fixture.php.inc
            /config
                rule.php
            CustomRuleName.php
```

## Tests

Next to the test case, there is `/Fixture` directory. It contains many test fixture files that verified the Rector rule work correctly in all possible cases.

There are 2 fixture formats:

A. `test_fixture.php.inc` - The Code Should Change

```php
<code before>
-----
<code after>'
```

B. `skip_rule_test_fixture.php.inc` - The Code Should Be Skipped

```php
<code before>
```

## Running the tests

To run a rector test fixture, add --filter to the test command.

```
vendor/bin/phpunit tests --filter AddVoidLifecycle

vendor/bin/phpunit tests --filter RemoveClassNamePrefixTest

vendor/bin/phpunit tests --filter ShortenShaExtendsTest
```

## Running rector on your PHP project

To see preview of suggested changed, run process command with `--dry-run` option:

```
vendor/bin/rector process --dry-run
```

To make changes happen, run bare command:

```
vendor/bin/rector process
```

## Rules

### Public Key Loader

This rule is for `v2` -> `v3` upgrade.

This rule helps to load unencrypted and encrypted public / private keys.

In `v2` `loadKey()` returns true on success and false on failure. `v2` only supports RSA keys and `$rsa` is *not* immutable.
And in `v3` `PublicKeyLoader` returns an immutable instance of either `\phpseclib3\Crypt\Common\PublicKey` or
`\phpseclib3\Crypt\Common\PrivateKey`. An exception is thrown on failure.

It replaces
```php
use phpseclib\Crypt\RSA;

$rsa = new RSA();
$rsa->loadKey('...');
```
with
```php
use phpseclib3\Crypt\PublicKeyLoader;

$rsa = PublicKeyLoader::load('...');
```

When `setPassword` is used, `$rsa->setPassword('password');` will be replaced with `$rsa = PublicKeyLoader::load('...', $password);`.

Additionally it replaces the following methods:

|               v2              |               v3              |
|-------------------------------|-------------------------------|
| $rsa->getSize()               | $rsa->getLength()             |
| $rsa->setHash('sha256');      | $rsa->withHash('sha256')      |
| $rsa->setMGFHash('sha256');   | $rsa->withMGFHash('sha256')   |
| $rsa->setSaltLength(10);      | $rsa->withSaltLength(10)      |
| $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);     | $rsa->withPadding(RSA::SIGNATURE_PKCS1);  |
| $rsa->setEncryptionMode(RSA::ENCRYPTION_PKCS1);   | $rsa->withPadding(RSA::ENCYRPTION_PKCS1); |
| $rsa->setEncryptionMode(RSA::ENCRYPTION_PKCS1); $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1); | $rsa->withPadding(RSA::SIGNATURE_PKCS1 | RSA::ENCYRPTION_PKCS1);|

### Public Key Loader Chained

Does the same things as `PublicKeyLoader`, but chains the methods.

The chaining option writes everything into _one_ line.
You can format them by running:

```sh
vendor/bin/php-cs-fixer fix path/to/file.php --rules=binary_operator_spaces,method_chaining_indentation
```

### Loading Encrypted Key

This rule is for `v2` -> `v3` upgrade.

It replaces
```php
use phpseclib\Crypt\RSA;
$rsa = new RSA();
extract($rsa->createKey(2048));
```
with
```php
use phpseclib3\Crypt\RSA;
$rsa = RSA::createKey(2048);
```

In `v2`, `$rsa->createKey()` returns an array with 3x parameters: `privatekey`, `publickey`, `partial`.
`privatekey` and `public key` are strings, partial can be ignored.

The above `v3` example returns an immutable instance of `phpseclib3\Crypt\Common\PrivateKey`.

The public key can be extracted by: `$rsa->getPublicKey()`.

### HashLength

This rule is for `v2` -> `v3` upgrade.

In phpseclib `v2` getLength would sometimes return the length in bits and sometimes it'd return the length in bytes
in phpseclib `v3` it was made consistent -
getLength always returns the length in bits and getLengthInBytes always returns the length in bytes.

It replaces
```php
use phpseclib\Crypt\Hash;
$hash = new Hash('sha512/224');
echo $hash->getLength();
```
with
```php
use phpseclib3\Crypt\Hash;
$hash = new Hash('sha512/224');
echo $hash->getLengthInBytes();
```

### SFTP File Size

This rule is for `v2` -> `v3` upgrade.

In phpseclib `v2` you have filemtime, fileatime, fileowner but, instead of filesize, you just have size?
phpseclib `v3` fixes that.

It replaces
```php
use phpseclib\Net\SFTP;

$sftp = new SFTP('...');
$sftp->login('username', 'password');
echo $sftp->size('/path/to/filename.ext');
```
with
```php
use phpseclib3\Net\SFTP;

$sftp = new SFTP('...');
$sftp->login('username', 'password');
echo $sftp->filesize('/path/to/filename.ext');
```
