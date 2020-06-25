use glob::glob;
use std::collections::HashMap;
use std::io::prelude::*;
#[macro_use]
extern crate serde_derive;
use std::path::PathBuf;
extern crate bindgen;
use std::env;

#[derive(Debug, Deserialize)]
struct IncludeMeta {
    includes: HashMap<String, Vec<String>>,
    output: String,
    header: String,
}
fn main() -> Result<(), Box<std::io::Error>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/include.toml");
    let reader = std::fs::File::open(path).unwrap();
    let mut string = String::new();
    std::io::BufReader::new(reader)
        .read_to_string(&mut string)
        .unwrap();
    let includes = toml::from_str::<IncludeMeta>(&mut string).unwrap();
    let mut bindings = bindgen::Builder::default();

    let mut header_file = std::io::BufWriter::new(std::fs::File::create(&includes.header).unwrap());
    write!(header_file, "#include <stdio.h>\n").unwrap();
    for (base, patterns) in includes.includes {
        for p in glob(&base).unwrap() {
            match p {
                Ok(p) => {
                    let include = String::from("-I") + p.to_str().unwrap();
                    //          println!("IncludePath: {:?}",include);
                    bindings = bindings.clang_arg(include);
                }
                Err(..) => {}
            }
        }
        for pattern in patterns {
            let path = base.clone() + &pattern;
            let mut p: Result<Vec<_>, _> =
                glob(&path).expect("Failed to read glob pattern").collect();
            let mut p = p.unwrap();
            p.sort_by(|a, b| {
                let a = a.with_file_name(a.file_stem().unwrap());
                let b = b.with_file_name(b.file_stem().unwrap());
                a.cmp(&b)
            });
            for entry in p {
                let header = entry.strip_prefix(&base).unwrap().to_str().unwrap();
                //       println!("Include Header: {}", header);
                write!(header_file, "#include \"{}\"\n", header).unwrap();
                //         bindings = bindings.header(header)
            }
        }
    }

    header_file.flush().unwrap();

    let bindings = bindings
        .header(&includes.header)
        .blacklist_item("_.*")
        .layout_tests(false)
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(includes.output)
        .expect("Couldn't write bindings!");
    Ok(())
}
