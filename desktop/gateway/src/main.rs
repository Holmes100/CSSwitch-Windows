fn main() {
    eprintln!("[gw] main() starting, args={:?}", std::env::args_os().collect::<Vec<_>>());
    let args_os: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let args: Vec<String> = args_os
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if args.get(1).map(String::as_str) == Some("skill-install-mcp") {
        if let Err(e) = csswitch_gateway::skill_install::run_mcp(&args[2..]) {
            eprintln!("csswitch-gateway skill installer: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("science-control") {
        match csswitch_gateway::science_control::run_cli(&args[2..]) {
            Ok(result) => println!("{result}"),
            Err(e) => {
                eprintln!("csswitch-gateway local Science control: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    match csswitch_gateway::config::GatewayConfig::from_env_args(args) {
        Ok(cfg) => {
            if let Err(e) = csswitch_gateway::server::serve(cfg) {
                eprintln!("csswitch-gateway: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("csswitch-gateway: {e}");
            std::process::exit(2);
        }
    }
}
