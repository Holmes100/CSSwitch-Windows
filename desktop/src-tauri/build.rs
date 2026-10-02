use std::path::{Path, PathBuf};
use std::process::Command;

fn gateway_bin_name() -> &'static str {
    if cfg!(windows) {
        "csswitch-gateway.exe"
    } else {
        "csswitch-gateway"
    }
}

fn stage_gateway_sidecar() {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let Ok(target) = std::env::var("TARGET") else {
        return;
    };
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("Desktop build must provide an OUT_DIR"));
    let manifest_dir = PathBuf::from(manifest_dir);
    let gateway_dir = manifest_dir.join("../gateway");
    if !gateway_dir.join("Cargo.toml").is_file() {
        return;
    }

    println!(
        "cargo:rerun-if-changed={}",
        gateway_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        gateway_dir.join("src").display()
    );
    println!("cargo:rerun-if-env-changed=CSSWITCH_SKIP_GATEWAY_STAGE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_ACCEPTANCE_BUILD");
    let acceptance_build = std::env::var_os("CARGO_FEATURE_ACCEPTANCE_BUILD").is_some();
    if std::env::var_os("CSSWITCH_SKIP_GATEWAY_STAGE").is_some() {
        panic!(
            "CSSwitch builds cannot skip Gateway staging; Desktop and Gateway build variants must match"
        );
    }

    // Never inherit the outer CARGO_TARGET_DIR for the nested build and then
    // read from a different default target directory. A private target root
    // under this exact Desktop build binds the copied sidecar to this build,
    // target triple, and feature selection.
    let gateway_target_dir = out_dir.join("gateway-target");
    let mut command = Command::new(&cargo);
    command
        .current_dir(&gateway_dir)
        .env("CARGO_TARGET_DIR", &gateway_target_dir)
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(&target);
    if acceptance_build {
        command.arg("--features").arg("acceptance-build");
    }
    let status = command.status();
    if !matches!(status, Ok(s) if s.success()) {
        panic!("failed to build csswitch-gateway sidecar for target {target}");
    }

    let built = gateway_target_dir
        .join(&target)
        .join("release")
        .join(gateway_bin_name());
    let out_dir = manifest_dir.join("binaries");
    std::fs::create_dir_all(&out_dir).expect("failed to create sidecar binaries dir");
    let mut staged_name = format!("csswitch-gateway-{target}");
    if cfg!(windows) {
        staged_name.push_str(".exe");
    }
    let staged = out_dir.join(staged_name);
    copy_executable(&built, &staged);
}

fn copy_executable(src: &Path, dst: &Path) {
    std::fs::copy(src, dst).unwrap_or_else(|e| {
        panic!(
            "failed to stage csswitch-gateway sidecar from {} to {}: {e}",
            src.display(),
            dst.display()
        )
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dst)
            .expect("failed to stat staged csswitch-gateway sidecar")
            .permissions();
        perms.set_mode(perms.mode() | 0o755);
        std::fs::set_permissions(dst, perms)
            .expect("failed to mark staged csswitch-gateway sidecar executable");
    }
}

/// libtest 测试二进制默认不嵌入应用 manifest；tauri/wry 引入的 comctl32
/// `TaskDialogIndirect` 只存在于 v6（SxS）。没有 Common-Controls v6 依赖声明时，
/// Windows loader 绑定到 v5.82 的 comctl32 → STATUS_ENTRYPOINT_NOT_FOUND，
/// 测试进程在 main 之前夭折（Tauri 在 Windows 上 `cargo test` 的已知平台限制）。
///
/// cargo 没有「仅 lib 单元测试」的 link-arg 指令，嵌入 manifest 又极易与
/// tauri-build 注入的资源撞成 CVT1100。因此这里改用【延迟加载】双保险：
/// 把 comctl32.dll 声明为 /DELAYLOAD——loader 启动时不再解析其静态导入，
/// 测试从不调用 TaskDialogIndirect，加载期失败即消失。用环境变量显式开启：
/// `set CSSWITCH_LINK_TEST_MANIFEST=1 && cargo test ...`；
/// cargo test 不链接 bin 目标，普通 build 完全不受影响。
fn delay_load_comctl32_for_tests() {
    println!("cargo:rerun-if-env-changed=CSSWITCH_LINK_TEST_MANIFEST");
    if std::env::var_os("CSSWITCH_LINK_TEST_MANIFEST").is_none() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rustc-link-arg=/DELAYLOAD:comctl32.dll");
    println!("cargo:rustc-link-arg=delayimp.lib");
}

fn main() {
    stage_gateway_sidecar();
    delay_load_comctl32_for_tests();
    tauri_build::build()
}
