# Contributing to phpseclib

This file covers how to set up a checkout and run the checks, which branch a change goes on, how to write and test it, and what PRs here should look like. To report a vulnerability, follow [SECURITY.md](SECURITY.md) instead.

## Getting started

1. Fork the Project

2. Ensure you have Composer installed (see [Composer Download Instructions](https://getcomposer.org/download/))

3. Install Development Dependencies
    ```sh
    composer install
    ```

4. Create a Feature Branch from the branch your change belongs on (see [Pick the right branch](#pick-the-right-branch))

5. Run continuous integration checks for the branch you are targeting:

   master and 4.0:
   ```sh
   composer run-script all-quality-tools
   ```

   3.0:
   ```sh
   composer global require php:^8.1 squizlabs/php_codesniffer friendsofphp/php-cs-fixer
   phpcs --standard=build/php_codesniffer.xml
   php-cs-fixer fix --config=build/php-cs-fixer.php --diff --dry-run --using-cache=no
   vendor/bin/phpunit --verbose --configuration tests/phpunit.xml
   ```

   1.0 and 2.0:
   ```sh
   vendor/bin/phpunit
   ```

6. Send us a Pull Request (see [PR titles and descriptions](#pr-titles-and-descriptions))

## Pick the right branch

The [Branches](README.md#branches) section of `README.md` lists each branch's minimum PHP version and namespace. master, the development branch, has the same ones as 4.0, and 1.0 uses PEAR-style class names like `Net_SSH2` and `Crypt_RSA`.

- Security fixes must reach every supported branch that has the vulnerable code, back to 1.0, so base them on the oldest one. Report the vulnerability and its fix privately, not in a PR (see [Security issues](#security-issues)).
- Bug fixes should also go back as far as possible, but that's optional: base the fix on the oldest branch that has the code you're changing (usually 1.0), or on any newer branch that has the bug.
- New features should go on master, but that's optional: you can base one on an older branch instead.
- The maintainers merge each branch into the next (1.0 → 2.0 → 3.0 → 4.0 → master) and port the change as they go, so a change reaches its base branch and every newer one. Open one PR, against the branch you picked.
- Keep backward compatibility on every branch except master. A change that breaks it must target master. That covers removing or renaming a class or a public or protected method, property or constant, changing their signatures, and changing behavior callers rely on. Protected members count because subclasses can use them. None of this applies to a class whose own docblock is tagged `@internal`. [VERSIONING.md](VERSIONING.md) has the full policy, including the `@removed` and `@changed` docblock tags that announce a future break.

## Writing code

- Write code for the minimum PHP version of the branch you're targeting. On 1.0 that means PHP 4 syntax: `var` properties, `array()`, and no namespaces, closures or `?:`.
- Match the style of the surrounding code on that branch: naming, formatting, docblocks and idioms. Each branch has its own (1.0 prefixes internal methods with `_`, 3.0 leaves signatures untyped, 4.0 types them), so don't carry style from one branch to another, and don't restyle code you aren't changing.
- In crypto code, don't branch, return early or index arrays on secret data, and don't replace constant-time comparisons such as `hash_equals()` with `==`, `===` or `strcmp()`. Code that looks redundant may be there to keep the timing constant.
- phpseclib must work without the optional math and crypto extensions; GMP, BCMath, OpenSSL, mcrypt and libsodium only speed it up. If you change behavior in one engine, check whether the others need the same change, and make sure each engine's tests cover it.

## Before opening a PR

- Run the checks for each branch you open a PR against, from step 5 of [Getting started](#getting-started). [.github/workflows/ci.yml](.github/workflows/ci.yml) has the full list CI runs.
- The SSH and SFTP tests in `tests/Functional` are skipped unless the `PHPSECLIB_SSH_*` environment variables point at a test server. The Tests job in `ci.yml` shows how CI sets one up.
- Every fix or feature needs a test that fails without the change and passes with it. Run the test before making the change to confirm it fails.
- PRs are merged without squashing, so every commit lands as is. A PR can have several commits, but each one should hold a complete fix or feature. Fold follow-up fixes into the commit they belong to and force-push, instead of adding fix-up commits.

## PR titles and descriptions

Start the PR's title with its base branch in brackets, like `[1.0] Fix X`.

Start its description with one to three sentences on what was wrong and what the change does. If it fixes an issue, mention the issue. `Closes #N` only closes it from a PR into master, the default branch; GitHub ignores the keyword in PRs into older branches.

## Security issues

Don't report vulnerabilities in a public issue or PR. Report them privately as [SECURITY.md](SECURITY.md) describes. That includes the fix: offer it in the private report instead of opening PRs, and the maintainers will say how they want it.
