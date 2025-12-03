### Fuzzing Kevi (cargo-fuzz)

This repo includes fuzz targets for security-critical parsing and decoding paths. Fuzzing is optional and intended for
contributors.

Prerequisites:

- Install cargo-fuzz (nightly toolchain recommended):

```
cargo install cargo-fuzz
```

Run targets:

- Header parser (`parse_kevi_header`):

```
cargo fuzz run fuzz_target_header_parse
```

- RON codec (decode robustness):

```
cargo fuzz run fuzz_target_ron_codec
```

Notes:

- Seed corpora under `fuzz/corpus/*` provide valid and invalid samples to start from.
- Fuzzing uses libFuzzer; crashes will be minimized and stored under `fuzz/artifacts/<target>/`.
- CI may run a short non-blocking smoke fuzz in the future; thorough fuzzing is best done locally.
