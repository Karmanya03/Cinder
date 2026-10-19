use std::env;
use std::fs::File;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../assets/Cinder-Logo.png");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let image = image::load_from_memory_with_format(
        include_bytes!("../assets/Cinder-Logo.png"),
        image::ImageFormat::Png,
    )
    .expect("Cinder logo PNG is readable")
    .to_rgba8();
    let mut directory = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16, 20, 24, 32, 40, 48, 64, 128, 256] {
        let resized =
            image::imageops::resize(&image, size, size, image::imageops::FilterType::Lanczos3);
        let icon = ico::IconImage::from_rgba_data(size, size, resized.into_raw());
        directory.add_entry(ico::IconDirEntry::encode(&icon).expect("encode Cinder icon size"));
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let ico_path = out_dir.join("cinder.ico");
    let mut file = File::create(&ico_path).expect("create generated Cinder ICO");
    directory
        .write(&mut file)
        .expect("write generated Cinder ICO");

    let mut resource = winres::WindowsResource::new();
    resource.set_icon(ico_path.to_str().expect("ICO path is UTF-8"));
    resource
        .compile()
        .expect("embed Cinder Windows application icon");

    // MinGW's archive linker drops the winres static library because resource
    // objects have no ordinary symbol references. Link the generated COFF
    // object directly so its icon and manifest resources are retained.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        println!(
            "cargo:rustc-link-arg={}",
            out_dir.join("resource.o").display()
        );
    }
}
