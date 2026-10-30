# AGENTS.md

Notes for AI coding agents working on phpseclib. `README.md` covers the library, its branches and how to run the checks; this file covers the rules it doesn't.

## Pick the right branch

phpseclib maintains five branches, each with its own minimum PHP version and class names:

| Branch | Minimum PHP | Classes                              |
|--------|-------------|--------------------------------------|
| 1.0    | 4           | PEAR-style (`Net_SSH2`, `Crypt_RSA`) |
| 2.0    | 5.3.3       | `phpseclib\`                         |
| 3.0    | 5.6.1       | `phpseclib3\`                        |
| 4.0    | 8.1         | `phpseclib4\`                        |
| master | 8.1         | `phpseclib4\` (development branch)   |

- Security fixes must reach every supported branch that has the vulnerable code, back to 1.0, so base them on the oldest one. Report the vulnerability privately first (see "Security issues").
- Bug fixes should also go back as far as possible, but that's optional: base the fix on the oldest branch that has the code you're changing (usually 1.0), or on any newer branch that has the bug.
- New features should go on master, but that's optional: you can base one on an older branch instead.
- A change goes on its base branch and every newer one, up to master. You merge it up yourself, with one PR per branch (see "Merging up").
- Keep backward compatibility on every branch except master. A change that breaks it must target master. That covers removing or renaming a class or a public or protected method, property or constant, changing their signatures, and changing behavior callers rely on. Protected members count because subclasses can use them. None of this applies to a class whose own docblock is tagged `@internal`. `VERSIONING.md` on 4.0 and master has the full policy, including the `@removed` and `@changed` docblock tags that announce a future break.

## Writing code

- Write code for the minimum PHP version of the branch you're targeting. On 1.0 that means PHP 4 syntax: `var` properties, `array()`, and no namespaces, closures or `?:`.
- Match the style of the surrounding code on that branch: naming, formatting, docblocks and idioms. Each branch has its own (1.0 prefixes internal methods with `_`, 3.0 leaves signatures untyped, 4.0 types them), so don't carry style from one branch to another, and don't restyle code you aren't changing.
- Use comments sparingly, and only to explain why the code does something, not what it does. The code already shows what it does.
- In crypto code, don't branch, return early or index arrays on secret data, and don't replace constant-time comparisons such as `hash_equals()` with `==`, `===` or `strcmp()`. Code that looks redundant may be there to keep the timing constant.
- phpseclib must work without the optional math and crypto extensions; GMP, BCMath, OpenSSL, mcrypt and libsodium only speed it up. If you change behavior in one engine, check whether the others need the same change, and make sure each engine's tests cover it.

## Before opening a PR

- Run the checks for each branch you open a PR against, from the "Contributing" section of `README.md`. `.github/workflows/ci.yml` has the full list CI runs.
- The SSH and SFTP tests in `tests/Functional` are skipped unless the `PHPSECLIB_SSH_*` environment variables point at a test server. The Tests job in `ci.yml` shows how CI sets one up.
- Every fix or feature needs a test that fails without the change and passes with it. Run the test before making the change to confirm it fails.
- PRs are merged without squashing, so every commit lands as is. A PR can have several commits, but each one should hold a complete fix or feature. Fold follow-up fixes into the commit they belong to and force-push, instead of adding fix-up commits.
- Don't have more than two changes open at once; a change's merge-up PRs count as one. Wait for one to be merged or closed before opening another, so the maintainers aren't flooded.

## Merging up

So the maintainers can merge every step on GitHub without resolving conflicts themselves, merge your change into each newer branch yourself, with one PR per branch. A fix based on 1.0 takes five PRs:

1. `my-fix` → 1.0: your commits
2. `my-fix-2.0` → 2.0: 2.0 with `my-fix` merged in
3. `my-fix-3.0` → 3.0: 3.0 with `my-fix-2.0` merged in
4. `my-fix-4.0` → 4.0: 4.0 with `my-fix-3.0` merged in
5. `my-fix-master` → master: master with `my-fix-4.0` merged in

- Use `git merge`, not a cherry-pick or a rebase onto the newer branch. When the maintainers later merge one branch into the next, git then finds your commits already there instead of conflicting with copies of them.
- Resolve conflicts in the merge commit, and port anything that merges cleanly but breaks on that branch, like 1.0 class names reaching 2.0. Run that branch's checks before pushing it.
- If an earlier PR changes, redo the merges after it and force-push those branches too.

## PR titles and descriptions

Start every PR's title with its base branch in brackets, like `[1.0] Fix X`. The merge-up PRs reuse the first PR's title with their own branch, like `[2.0] Fix X`.

Start the first PR's description with one to three sentences on what was wrong and what the change does. Once the merge-up PRs are open, end it with a link to each of them, in merge order:

```markdown
Merged up by:

- 2.0: #1235
- 3.0: #1236
- 4.0: #1237
- master: #1238
```

Start each merge-up PR's description with the PR it merges, e.g. `Merges #1234 into 2.0.` If the merge had conflicts or needed a port, add a sentence or two on what it changed on that branch and why. The PR's diff shows the rest.

## Security issues

Don't report vulnerabilities in a public issue or PR. Use the Tidelift security contact in `SECURITY.md`.
