# Rector

phpseclib uses [Rector](https://getrector.com/) that you can run on any PHP project to get an instant upgrade or automated refactoring.

## Rector file structure

Rector works with `rector.php` config file. This is located at the project root and this is where you define the project path and rules to be implemented.

Both configured and custom rule are used here. Configured rules are directly added to the `rector.php` file and custom rules are added to the `rules` folder.

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
vendor/bin/phpunit tests --filter AddVoidLifecycleAssertTest

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
