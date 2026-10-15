# Psalm to PHPStan migration remarks

This file summarizes noteworthy decisions and known analysis differences
introduced while replacing Psalm with PHPStan. Detailed investigation artifacts
are kept under `analysis/`.

## Analyzer differences

### `new static()` constructor checking

phpseclib intentionally uses late-static construction in numeric/arithmetic and
helper hierarchies. No incompatible in-tree constructor was found for the
reviewed calls. PHPStan reports these extensible calls as `new.static`; narrow,
count-guarded exceptions cover the reviewed files rather than changing their
constructor, finality or inheritance contracts. This does not guarantee that
arbitrary external subclasses are safe.

This accepts a known constructor-call coverage difference from Psalm. The previous
Psalm level-6 gate treated the structural extension risk as informational, but
could still report definite argument-type or missing-argument errors at these
calls. PHPStan 2.2.16 does not perform equivalent argument checking for unconstrained,
overridable `new static()` calls, and suppressing the warning does not restore
it. Restoring that coverage would require stronger constructor contracts or
hierarchy restrictions, considered disproportionate and potentially API-affecting
for this migration.

## Migration changes

For the dynamic BigInteger Engine/provider hierarchy, the previous global Psalm
`UndefinedMethod` suppression was replaced with path-, message- and count-limited
PHPStan exceptions for the 35 reviewed instance/static capability calls. This
retains the practical tolerance for runtime-selected protected/provider methods
without inventing a universal public Engine/provider API. The exceptions do not
cover return, argument, property or other missing-method diagnostics. They also
do not restore argument checking where PHPStan cannot resolve a method signature.

This section will contain short explanations of noteworthy migration commits
and changes as the migration is finalized.
