use std::{env, path::Path, process::Command};

fn main() {
    if env::var_os("CARGO_FEATURE_SIGNATURE_LINK").is_none() {
        return;
    }
    let source = Path::new("../source");
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(source)
        .output()
        .expect("read SDK checkout");
    assert!(head.status.success(), "cannot identify SDK checkout");
    assert_eq!(
        String::from_utf8(head.stdout).unwrap().trim(),
        "8b356f8ae966e206204301b169f1d1169520d554",
        "SDK revision differs from current profile"
    );
    assert!(
        Command::new("git")
            .args(["diff", "--quiet", "HEAD", "--"])
            .current_dir(source)
            .status()
            .expect("check SDK changes")
            .success(),
        "SDK has tracked changes"
    );
    println!("cargo:rerun-if-changed=../source");
}
