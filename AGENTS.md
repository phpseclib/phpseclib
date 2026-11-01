# AGENTS.md

Notes for AI coding agents working on phpseclib. Follow [CONTRIBUTING.md](CONTRIBUTING.md): it has the rules every contributor follows, including which branch to use, how to write and test code and how to write PRs. It points to [README.md](README.md) for the branches and to [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

On top of those:

- Don't proactively look for bugs in 1.0, 2.0 or 3.0; look on 4.0 or master instead. A bug that users report on an older branch, or that you find on 4.0 and an older branch shares, can still be fixed there under the rules in `CONTRIBUTING.md`.
- Use comments sparingly, and only to explain why the code does something, not what it does. The code already shows what it does.
- Unlike other contributors, merge your change up yourself (see [Merging up](#merging-up)), instead of opening one PR and leaving the merge-up to the maintainers.
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
- If a newer branch no longer has the code you changed, its merge keeps that branch's own version and its PR changes no files. Open that PR anyway and say why it changes nothing; otherwise the maintainers hit the same conflict the next time they merge the older branch into it.
- If an earlier PR changes, redo the merges after it and force-push those branches too.

## Merge-up PR titles and descriptions

The first PR follows [PR titles and descriptions](CONTRIBUTING.md#pr-titles-and-descriptions) in `CONTRIBUTING.md`. Once the merge-up PRs are open, end its description with a link to each of them, in merge order:

```markdown
Merged up by:

- 2.0: #1235
- 3.0: #1236
- 4.0: #1237
- master: #1238
```

Give each merge-up PR the first PR's title with its own branch, like `[2.0] Fix X`, and start its description with the PR it merges, e.g. `Merges #1234 into 2.0.` If the merge had conflicts or needed a port, add a sentence or two on what it changed on that branch and why. The PR's diff shows the rest.

If the change fixes an issue, put `Closes #N` in the description of the PR into master, the only one GitHub closes issues from.
