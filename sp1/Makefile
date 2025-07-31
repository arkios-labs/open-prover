BINARY_NAME = sp1-cpu

build:
	cargo build --release
	cp ../target/release/sp1 ./$(BINARY_NAME)

build-gpu:
	cargo build --release --features=gpu
	cp ../target/release/sp1 ./$(BINARY_NAME)
