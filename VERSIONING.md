# phpseclib Versioning and Breaking Change Policy

This document outlines the formal policy for versioning, deprecations, and backward compatibility (BC) for phpseclib.

## Versioning Strategy: RomVer
phpseclib adheres to **RomVer** (Project.Major.Minor). Version increments are defined as follows:

* **PROJECT:** Incremented when the library is considered a new, separate project or undergoes a total paradigm shift (e.g., the transition from v3.0 to v4.0).
* **MAJOR:** Incremented when intentional breaking changes (BC) are introduced to the existing API.
* **MINOR:** Incremented for new features, bug fixes, and security patches that maintain full backward compatibility.

## Long-Term Support (LTS) & Maintenance
To provide stability for enterprise users, all **MAJOR** releases are treated as Long-Term Support (LTS) branches. 

* **End-of-Life (EOL) Notice:** In the event that a Major version is slated for End-of-Life (cessation of security patches and bug fixes), notice will be posted prominently in the `README.md` and on the official website at least **one year (12 months) in advance**.
* **Legacy Support:** This policy ensures that developers have a predictable window to plan and execute migrations before support for a legacy branch is withdrawn.

## Breaking Change Policy
To ensure stability for enterprise integrations and mission-critical applications:
1.  **Stability Guarantee:** Breaking changes are strictly prohibited within **Minor** version increments. Users may safely automate updates within a Major series (e.g., `^3.0`) without risk of API breakage.
2.  **Consolidation:** Intentional breaking changes are consolidated into **Major** or **Project** releases. 
3.  **Bug Fixes:** While bug fixes may technically alter behavior that a developer was unintentionally relying on, these are not considered policy-breaking changes and will be released in Minor versions.

## Deprecation and Future-Proofing
phpseclib does not use traditional `E_USER_DEPRECATED` notices for most changes to avoid disrupting production environments. Instead, a "Version-Targeted" communication strategy is used in the source code documentation.

### Informational Tags
Rather than generic deprecation warnings, phpseclib utilizes specific PHPDoc tags to signal future state:

* **`@removed in phpseclib [version]`**: Indicates that the specific method, class, or property is stable in the current version but will be removed entirely in the specified future version.
* **`@changed in phpseclib [version]`**: Indicates that the API signature (e.g., parameter order or type-hinting) will be altered in the specified version.

### Persistence Guarantee
Any feature marked with `@removed` or `@changed` is **guaranteed to remain functional** in its current state for the remainder of the current Project/Major version's lifecycle. These tags serve as a long-term roadmap for developers, providing the necessary time to plan migrations without immediate pressure.

## Migration Support
For Project-level transitions (e.g., v3.0 to v4.0), phpseclib commits to providing:
1.  **Migration Guides:** Dedicated documentation outlining the differences between the legacy and modern APIs.
2.  **Implementation Examples:** Side-by-side code comparisons to assist developers in adapting to new paradigms.