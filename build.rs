// DEBTS.md item 17: nothing enforced that `src/dsdt.aml` (the compiled
// binary actually embedded via `include_bytes!`) stayed in sync with
// `acpi/dsdt.asl` (the checked-in source). If `iasl` is installed, this
// recompiles the source into a scratch location and compares the bytes,
// failing the build on a mismatch. If `iasl` isn't installed, this is a
// no-op — hyperbug's own `cargo build` doesn't need it, only editing the
// DSDT does (see docs/dev-guide.md's toolchain notes).

use std::path::Path;
use std::process::Command;

fn main() {
    let asl_path = "acpi/dsdt.asl";
    let embedded_aml_path = "src/dsdt.aml";
    println!("cargo:rerun-if-changed={asl_path}");
    println!("cargo:rerun-if-changed={embedded_aml_path}");

    if Command::new("iasl").arg("-v").output().is_err() {
        println!(
            "cargo:warning=iasl not found — skipping DSDT source/binary drift check (DEBTS.md item 17); \
             install `acpica` to enable it"
        );
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let scratch_asl = Path::new(&out_dir).join("dsdt.asl");
    std::fs::copy(asl_path, &scratch_asl).expect("copy dsdt.asl to OUT_DIR for a scratch compile");

    let out_prefix = Path::new(&out_dir).join("dsdt");
    let status = Command::new("iasl")
        .args(["-p", &out_prefix.to_string_lossy()])
        .arg(&scratch_asl)
        .status()
        .expect("run iasl");
    if !status.success() {
        panic!("iasl failed to compile {asl_path} — see output above");
    }

    let recompiled = out_prefix.with_extension("aml");
    let fresh = std::fs::read(&recompiled).expect("read freshly-compiled dsdt.aml");
    let embedded = std::fs::read(embedded_aml_path).expect("read the embedded dsdt.aml");
    if fresh != embedded {
        panic!(
            "{embedded_aml_path} is out of sync with {asl_path} — recompile with \
             `iasl {asl_path}` and copy the result: `cp acpi/dsdt.aml {embedded_aml_path}`"
        );
    }
}
