fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let proto_file = "../bitevachat-rpc/proto/bitevachat.proto";
    let proto_dir = "../bitevachat-rpc/proto";

    println!("cargo:rerun-if-changed={proto_file}");

    if !std::path::Path::new(proto_file).exists() {
        return Err(format!(
            "proto file not found at '{proto_file}' \
             (cwd: {:?}). Ensure bitevachat-rpc/proto/bitevachat.proto exists.",
            std::env::current_dir().unwrap_or_default(),
        )
        .into());
    }

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_dir])?;

    Ok(())
}