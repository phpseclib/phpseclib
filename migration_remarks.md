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

### Backend-owned `$value` property checking

The BigInteger engines keep their numeric state in a `$value` property owned by
each concrete backend (GMP `string|\GMP`, BCMath `string`, PHP engines
`string|array`), while shared algorithms in the abstract `Engine` read and
write it without PHPStan being able to bind the access to a concrete owner.
Narrow, count-guarded PHPStan exceptions cover exactly those reviewed
`$value` `property.notFound` occurrences in `Math/BigInteger/Engines/Engine.php`
(18 Engine-receiver plus 2 template occurrences) and `GMP.php` (5 occurrences),
mirroring the previous effective Psalm tolerance. No universal Engine `$value`
contract was declared, and PHPStan's broader `property.notFound` category
(other properties, other files, incompatible assignments) remains fully
checked.

### Subclass-owned EC `$factory` property

EC curve classes keep their scalar-field factory in a `$factory` property
declared only on the concrete families (`PrimeField` for
prime/Montgomery/TwistedEdwards curves, `BinaryField` for binary curves),
while shared methods in the abstract `Crypt\EC\BaseCurves\Base` read it, which
PHPStan reports as `property.notFound`. The four universal field operations
(`randomInteger`, `newInteger`, `getLengthInBytes`, `getLength`) carry local,
line-scoped PHPStan ignores mirroring the previous per-method Psalm
suppressions. The fifth access in `setReduction()` deliberately remains
visible as the standing marker for the known defect BI-013 (`BinaryField` has
no `setReduction`). No `$factory` type contract, hierarchy, or runtime change
was introduced.

## Migration changes

For the dynamic BigInteger Engine/provider hierarchy, the previous global Psalm
`UndefinedMethod` suppression was replaced with PHPStan exceptions bounded to
the reviewed Engine/provider files: `method.notFound` in
`Math/BigInteger/Engines/Engine.php` (count-guarded) and
`staticMethod.notFound` in the six reviewed engine files, covering the 35
reviewed instance/static capability calls. This retains the practical
tolerance for runtime-selected protected/provider methods without inventing a
universal public Engine/provider API. The exceptions do not cover return,
argument or property diagnostics, and they do not restore argument checking
where PHPStan cannot resolve a method signature. Missing-method diagnostics
outside the reviewed files remain visible; inside them, future missing-method
typos are tolerated, as under the previous global Psalm allowance.

This section will contain short explanations of noteworthy migration commits
and changes as the migration is finalized.
