use clap::{App, Arg, SubCommand};
use log::{debug, error};
use std::path;
use std::process;
use container;

fn main() {
    container::init_logger();
    let app = App::new("Minimal linux container tool!")
        .version("0.1.0")
        .author("sun <github.com/wszxl516>")
        .usage("")
        .subcommand(
            SubCommand::with_name("start")
                .about("start container")
                .arg(
                    Arg::with_name("name")
                        .short("n")
                        .takes_value(true)
                        .value_name("name")
                        .default_value("container")
                        .help("container host name")
                        .required(false),
                )
                .arg(
                    Arg::with_name("root")
                        .short("r")
                        .takes_value(true)
                        .value_name("root")
                        .help("container root filesystem")
                        .required(true),
                )
                .arg(
                    Arg::with_name("init")
                        .short("i")
                        .takes_value(true)
                        .value_name("init")
                        .help("init process of container")
                        .default_value("/init")
                        .required(false),
                )
                .arg(
                    Arg::with_name("args")
                        .short("a")
                        .takes_value(true)
                        .value_name("args")
                        .help("arguments for init process!")
                        .required(false),
                )
                .arg(
                    Arg::with_name("env")
                        .short("e")
                        .takes_value(true)
                        .value_name("env")
                        .help("environment variables for init process!")
                        .required(false),
                )
                .arg(
                    Arg::with_name("out-addr")
                        .short("o")
                        .takes_value(true)
                        .value_name("out")
                        .help("veth pair of outside namespace one ip address!")
                        .default_value("10.0.0.1/24")
                        .required(false)
                )
                .arg(
                    Arg::with_name("ns-addr")
                        .short("s")
                        .takes_value(true)
                        .value_name("out")
                        .help("veth pair of inside namespace one ip address!")
                        .default_value("10.0.0.2/24")
                        .required(false)
                )
            ,
        )
        .subcommand(
            SubCommand::with_name("enter")
                .about("enter a container with a command!")
                .arg(
                    Arg::with_name("pid")
                        .short("p")
                        .takes_value(true)
                        .value_name("pid")
                        .help("pid of target namespace!")
                        .required(true),
                )
                .arg(
                    Arg::with_name("cmd")
                        .short("c")
                        .takes_value(true)
                        .value_name("cmd")
                        .help("command to run!")
                        .required(true),
                )
                .arg(
                    Arg::with_name("bg")
                        .short("b")
                        .help("run in back ground")
                        .default_value("false")
                        .required(false),
                ),
        )
        .setting(clap::AppSettings::ArgRequiredElseHelp);
    let matches = app.get_matches();
    match matches.subcommand_matches("enter") {
        None => {}
        Some(arg_matches) => {
            let pid = arg_matches.value_of("pid").unwrap().parse::<i32>().unwrap();
            let cmd = arg_matches
                .value_of("cmd")
                .unwrap()
                .split(" ")
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            let bg = arg_matches.is_present("bg");
            container::Enter::new(pid, container::Args { record: cmd }, container::Env::default(), bg)
                .start(||{})
                .unwrap_or_else(|e| error!("{}", e.to_string()));
        }
    }
    match matches.subcommand_matches("start") {
        None => {}
        Some(arg_matches) => {
            let init = arg_matches.value_of("init").unwrap_or("/init");
            let env_list = arg_matches
                .value_of("env")
                .unwrap_or("")
                .split(" ")
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            let mut env = container::Env::default();
            for e in env_list {
                let (key, value) = e.split_once("=").unwrap_or(("", ""));
                if key.is_empty() || value.is_empty() {
                    continue;
                }
                env.insert(key.to_string(), value.to_string());
            }
            let args_list = arg_matches
                .value_of("args")
                .unwrap_or("")
                .split(" ")
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            let mut args = container::Args::new();
            args.insert(init.to_string());
            for arg in args_list {
                if !arg.is_empty() {
                    args.insert(arg)
                }
            }
            let name = arg_matches.value_of("name").unwrap_or("container");
            let root = arg_matches.value_of("root").unwrap();
            debug!("{} {} {} {} {}", name, root, init, args, env);
            path::Path::new(format!("{}{}", root, init).as_str())
                .exists()
                .eq(&false)
                .then(|| {
                    error!(
                        "init [{:?}] not exists!",
                        format!("{}{}", root, init).as_str()
                    );
                    process::exit(1);
                });

            container::Container::new(name,
                                      root,
                                      init,
                                      args,
                                      env,
                                      arg_matches.value_of("out-addr").unwrap().to_string(),
                                      arg_matches.value_of("ns-addr").unwrap().to_string())
                .start()
                .unwrap_or_else(|e| error!("{:?}", e))
        }
    }
}
