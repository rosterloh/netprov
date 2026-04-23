fn main() {
    // Recompile if the committed dev key changes.
    println!("cargo:rerun-if-changed=../../packaging/dev-key.bin");
}
