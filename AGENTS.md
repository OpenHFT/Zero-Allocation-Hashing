# Zero-Allocation Hashing AGENTS

- Follow repository `AGENTS.md` as the base rules; this file adds module specifics. Durable docs live in `src/main/docs/` with the landing page at `README.adoc`.
- Module purpose: zero-allocation hashing primitives and utilities for bytes/arrays/buffers with stable, cross-platform output.
- Build commands: full build `mvn -q clean verify`; module-only without tests `mvn -pl zero-allocation-hashing -am -DskipTests install`.
- Quality gates: keep Checkstyle/SpotBugs clean; preserve deterministic hash outputs across platforms; avoid hidden allocations in hot paths.
- Documentation: maintain Nine-Box IDs in `src/main/docs/specifications.adoc`/`project-requirements` if added, and link decisions/tests accordingly; British English, ASCII/ISO-8859-1, `:source-highlighter: rouge`.
- Guardrails: changes to hashing outputs are breaking; document any algorithm/version bumps; call out platform-specific behaviour in `unsafe-and-platform-notes.adoc`.
