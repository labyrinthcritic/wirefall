fn main() {
    println!("cargo:rustc-link-lib=nftables");

    let bindings = bindgen::Builder::default()
        .header("include/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .ctypes_prefix("libc")
        .allowlist_item("nft_.*|NFT_.*")
        .generate()
        .unwrap();

    bindings.write_to_file("src/bindings.rs").unwrap();
}
