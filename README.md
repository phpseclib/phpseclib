# phpseclib - "Stable" fork with warnings

Do not use in your application unless you read the warning below:

This library is intended only to allow "stable" dependency on phpseclib's 3.0
branch. Upstream's v3.0 branch is namespaces to make it distinct from phpseclib
<=2.0, so this library can be istalled alongside an existing phpseclib stable
library. That said Your Mileage May Vary and this is not going to be subject
to extensive testing.

By all means raise an issue for this fork at
[GitHub](https://github.com/liamdennehy/phpseclib/issues), but these will likely
turn into upstream fixes first so will take longer, and then only to ensure
compatibiltiy between 3.0 and 2.0 installs on the same system.

Once 3.0 stabilises, this library will be deprecated and users encouraged to
move to the upstream instead.
