# AGENTS.md

## Scope
- Java 8+ hashing library; single-module Maven build.
- Public API in `net.openhft.hashing` should remain stable unless explicitly requested.

## Build and test
- Prefer `./mvnw` to match the repo Maven version.
- Preferred full check:
  - `mkdir -p logs`
  - `./mvnw verify -l logs/mvn-verify.log`
- Test example:
  - `./mvnw test -l logs/mvn-test.log`
- Fast compile:
  - `./mvnw -DskipTests package -l logs/mvn-skip-tests.log`
- Review logs:
  - `rg -n '^\[(WARNING|ERROR)\]|SLF4J\(W\)|\bWARNING:|\bwarning:' logs/mvn-verify.log`
- Do not commit logs/.

## Repo map
- Main code: `src/main/java`.
- JDK stub classes: `src/main/java-stub` (keep signatures aligned).
- Docs: `src/main/docs/`.
- Tests use JUnit 4 in `src/test/java`.

## Constraints
- Java baseline: 8 (avoid newer language features).
- Source files must stay ISO-8859-1 (code points 0-255). Prefer ASCII; avoid smart quotes and non-breaking spaces.
- Treat warnings as defects; keep logs clean.
- Avoid extra allocations, boxing, streams, or synchronisation on hashing hot paths.
- Keep endian and platform behaviour consistent with existing algorithms.
- Unsafe and DirectBuffer usage is intentional; maintain JDK 8 compatibility.

## Docs and review checklist
- Update `src/main/docs/` when public behaviour changes.
- Note any skipped suites in summaries.
- For large mechanical changes, declare the transformation rule and keep it consistent.

## References
- `OpenHFT/docs/Company-Wide-Tagging.adoc` for tagging and decision record templates.
