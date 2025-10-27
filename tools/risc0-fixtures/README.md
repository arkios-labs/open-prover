# How to generate risc0 test fixtures

```
cargo run --release
```

The fixtures will be generated in the `metadata` directory.

```
ls -l metadata
```

Copy the `metadata` directory to the `risc0` directory.

```
cp -r metadata ../../risc0/metadata
```

You can now use the new fixtures in the `risc0` directory.