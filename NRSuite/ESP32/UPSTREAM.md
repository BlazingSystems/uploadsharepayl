# ESP32 upstream reference

The canonical ESP32 firmware remains upstream rather than being duplicated and silently diverged here.

- Repository: `7wp81x/NRSuite-firmware`
- Audited commit: `0566adf0eaa1ed133c97c308c1ae17409cd0d59c`
- Release line: `v1.0.0-beta.2`
- Protocol: NRSuite v1.0

The upstream build already enables size-oriented compiler/linker settings (`-Os`, function/data sections, and garbage collection) and keeps feature selection board-specific. Any future optimization of the ESP32 target should be benchmarked against this pinned commit rather than changing behavior speculatively.

This monorepo port does not rewrite active attack/credential-capture modules. Use the canonical upstream repository when comparing ESP32 behavior and licensing.
