fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../idl/proto/a41/zkrabbit/agent/v0/risc0.proto")?;
    Ok(())
}
