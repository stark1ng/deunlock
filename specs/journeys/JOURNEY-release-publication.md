# Publish installable releases and documentation

## User journey

A reader opens the repository, follows its visible documentation link, installs the latest desktop package with one command, downloads the signed Android companion, and completes the existing pairing and PAM setup guides. A maintainer can reproduce the artifacts from a tagged source revision and retain the same Android signing identity across releases.

## Requirements

- Publish the checked MkDocs site through GitHub Pages and expose its URL on the repository.
- Replace the live README with the reviewed documenter structure and working installation, documentation, release, development, maintainer, and license links.
- Build native DEB, RPM, and Arch Linux packages plus manual Linux archives for x86_64 and aarch64. Include the CLI, PAM module, daemon, and systemd user unit.
- Test package installation in containers; package installation must preserve existing bond state and must not edit PAM configuration or start a privileged authentication policy automatically.
- Build the four-ABI Android Rust library, compile the release APK, sign it with a persistent protected key, and verify its certificate against the public certificate committed to the repository.
- Publish versioned GitHub release artifacts with checksums and build/source metadata.
- Provide a POSIX shell installer that selects a native package from one resolved release and verifies its checksum before invoking the package manager.
- Document direct release downloads, installer behavior, signing verification, source builds, and explicit post-install configuration.
- Keep audit files out of commits.

## Stressors and defenses

| Stressor | Defense |
| --- | --- |
| Latest release changes during installation | Resolve one tag before downloading its package and checksums. |
| Corrupted or truncated artifact | Check the exact SHA-256 entry before package-manager execution. |
| Unsupported distribution or architecture | Refuse installation with an actionable message. |
| Newer build-host libc | Build on Debian 12 and declare the corresponding runtime floor. |
| Different PAM library directories | Package a distribution-appropriate module path. |
| Existing bond ownership on upgrade | Preserve state and verify an upgrade against preexisting storage. |
| Misconfigured PAM causes loss of access | Never edit PAM stacks from package hooks or the download installer. |
| Missing signing credentials | Fail the release build; never substitute a debug key. |
| Android signing key changes | Compare the APK certificate with the checked-in public certificate. |
| Secret leakage | Store private material outside the repository and in encrypted GitHub environment secrets; pass passwords through environment variables. |
| Partial release build | Publish only after all architecture, Android, and package-smoke jobs succeed. |
| Untrusted pull request | Deploy Pages only from the default branch; sign/publish only from trusted manual/tag workflows. |
| Stale release filenames | Derive artifact names from validated version and architecture values. |
| Broken project-subpath URLs | Build with the Pages site URL and test the published site and installer. |

## Acceptance and evidence

Existing authentication mechanics and specification decisions remain unchanged.

- The real four-ABI Rust AAR build and signed Gradle release build pass. APK version is 0.1.0, version code 1000, and certificate SHA-256 matches the committed public certificate. The optimized launcher PNG matches the owner's logo pixel for pixel.
- Native Fedora 44, Arch, and openSUSE container install/reinstall/remove checks pass with preserved bond ownership/content and unchanged preexisting PAM files. Debian/Ubuntu checks use the workflow's Debian 12 binaries because the developer-host binaries require a newer glibc.
- The Python release and installer suite passes 31 tests. ShellCheck and actionlint pass for the release scripts and workflows.
- The complete documentation browser checker passes with 14 HTML pages and all 20 illustrated chapters. Adding the project Pages URL exposed an absolute `/deunlock/` link in the generated 404 page; the link checker now resolves that configured project prefix against the site root.
- `make lint` passes with the three existing allowed dependency maintenance advisories. `make test` passes with 447 passed and 9 ignored.
- GitHub Pages is configured to use Actions; the repository homepage points to `https://dmytrogajewski.github.io/deunlock/`. The `release` environment holds the persistent Android signing secrets, with a private backup outside the repository.
- The first hosted Android setup failed because the setup action's default package list includes the removed SDK package `tools`. The workflow explicitly requests `platform-tools`; platform, Build Tools, and NDK versions remain pinned in the following step.

## Published result

- [PR #3](https://github.com/dmytrogajewski/deunlock/pull/3) merged at `285ccf4fadee4a0e88826dc3fe6cefc4e79cd2f3`; annotated tag `v0.1.0` points to that commit.
- [The tagged release workflow](https://github.com/dmytrogajewski/deunlock/actions/runs/39347479789) passed both Linux builds, all seven distribution-install probes, the four-ABI signed Android build, artifact assembly, and publication.
- [Release v0.1.0](https://github.com/dmytrogajewski/deunlock/releases/tag/v0.1.0) is public with 15 assets. Downloaded files pass all 14 entries in `SHA256SUMS`; `release.json` records the tagged merge commit.
- The downloaded APK passes `apksigner verify`, matches the pinned certificate, and contains the owner's exact logo pixels (`compare -metric AE` reports zero).
- The live Pages home, three illustrated mechanics scenes, chapter controls, and search pass a browser probe with no JavaScript errors. Published installer, image, JavaScript, and CSS bytes match their committed sources.
- Fetching the live installer and running `--dry-run` resolves the public latest release, downloads and verifies `deunlock-0.1.0-4.x86_64.rpm`, and selects `dnf` without changing the developer machine.
- The documentation follow-up adds direct published APK/checksum links to the home page and pins the README APK link to its matching versioned release.
