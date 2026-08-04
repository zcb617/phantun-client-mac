use clap::{Arg, ArgAction, ArgMatches, Command, crate_version};
use log::error;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub dest: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_local")]
    pub local: String,
    #[serde(default = "default_remote")]
    pub remote: String,
    #[serde(default)]
    pub ipv4_only: bool,
    #[serde(default = "default_tun_local")]
    pub tun_local: String,
    #[serde(default = "default_tun_peer")]
    pub tun_peer: String,
    #[serde(default = "default_tun_local6")]
    pub tun_local6: String,
    #[serde(default = "default_tun_peer6")]
    pub tun_peer6: String,
    #[serde(default)]
    pub routes: Vec<Route>,
}

pub fn default_local() -> String {
    "127.0.0.1:8080".to_owned()
}

pub fn default_remote() -> String {
    "127.0.0.1:65000".to_owned()
}

pub fn default_tun_local() -> String {
    "192.168.200.1".to_owned()
}

pub fn default_tun_peer() -> String {
    "192.168.200.2".to_owned()
}

pub fn default_tun_local6() -> String {
    "fcc8::1".to_owned()
}

pub fn default_tun_peer6() -> String {
    "fcc8::2".to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            local: default_local(),
            remote: default_remote(),
            ipv4_only: false,
            tun_local: default_tun_local(),
            tun_peer: default_tun_peer(),
            tun_local6: default_tun_local6(),
            tun_peer6: default_tun_peer6(),
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub local: String,
    pub remote: String,
    pub ipv4_only: bool,
    pub tun_local: String,
    pub tun_peer: String,
    pub tun_local6: String,
    pub tun_peer6: String,
    pub routes: Vec<Route>,
}

impl RuntimeConfig {
    pub fn from_matches(matches: &ArgMatches) -> Self {
        let mut config = load_config("phantun-client.json");
        if let Some(config_path) = matches.get_one::<String>("config") {
            config = load_config(config_path);
        }

        Self::from_loaded_config(matches, config)
    }

    pub fn from_loaded_config(matches: &ArgMatches, config: Config) -> Self {
        Self {
            local: matches
                .get_one::<String>("local")
                .cloned()
                .unwrap_or(config.local),
            remote: matches
                .get_one::<String>("remote")
                .cloned()
                .unwrap_or(config.remote),
            ipv4_only: matches.get_flag("ipv4_only") || config.ipv4_only,
            tun_local: matches
                .get_one::<String>("tun_local")
                .cloned()
                .unwrap_or(config.tun_local),
            tun_peer: matches
                .get_one::<String>("tun_peer")
                .cloned()
                .unwrap_or(config.tun_peer),
            tun_local6: config.tun_local6,
            tun_peer6: config.tun_peer6,
            routes: config.routes,
        }
    }
}

pub fn load_config(path: &str) -> Config {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|error_value| {
            error!(
                "Failed to parse config file {}: {}, using defaults",
                path, error_value
            );
            Config::default()
        }),
        Err(error_value) => {
            error!(
                "Failed to read config file {}: {}, using defaults",
                path, error_value
            );
            Config::default()
        }
    }
}

pub fn select_remote_address<I>(addresses: I, ipv4_only: bool) -> Option<SocketAddr>
where
    I: IntoIterator<Item = SocketAddr>,
{
    addresses
        .into_iter()
        .find(|address| !ipv4_only || address.is_ipv4())
}

pub fn command() -> Command {
    Command::new("Phantun Client")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .required(false)
                .value_name("PATH")
                .help("Path to config file (default: phantun-client.json in current directory)"),
        )
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(false)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Phantun Client listens for incoming UDP datagrams"),
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(false)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Client connects to Phantun Server"),
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)"),
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end)"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_windows_client_source() {
        assert_eq!(Config::default().local, "127.0.0.1:8080");
        assert_eq!(Config::default().remote, "127.0.0.1:65000");
        assert!(!Config::default().ipv4_only);
        assert_eq!(Config::default().tun_local, "192.168.200.1");
        assert_eq!(Config::default().tun_peer, "192.168.200.2");
        assert_eq!(Config::default().tun_local6, "fcc8::1");
        assert_eq!(Config::default().tun_peer6, "fcc8::2");
    }

    #[test]
    fn distributed_config_template_matches_the_windows_client_template() {
        let config: Config = serde_json::from_str(include_str!("../../phantun-client.json"))
            .expect("the distributed configuration template must be valid JSON");

        assert_eq!(config.local, "127.0.0.1:8080");
        assert_eq!(config.remote, "120.26.71.147:65009");
        assert!(config.ipv4_only);
        assert_eq!(config.tun_local, "192.168.200.1");
        assert_eq!(config.tun_peer, "192.168.200.2");
        assert_eq!(config.tun_local6, "fcc8::1");
        assert_eq!(config.tun_peer6, "fcc8::2");
        assert_eq!(
            config.routes,
            vec![Route {
                dest: "0.0.0.0/0".to_owned(),
                gateway: "192.168.200.1".to_owned(),
            }]
        );
    }

    #[test]
    fn cli_contract_has_the_windows_options() {
        let command = command();
        let option_ids = command
            .get_arguments()
            .map(|argument| argument.get_id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            option_ids,
            [
                "config",
                "local",
                "remote",
                "ipv4_only",
                "tun_local",
                "tun_peer"
            ]
        );
    }

    #[test]
    fn cli_values_override_loaded_defaults() {
        let matches = command()
            .try_get_matches_from([
                "phantun-client",
                "--local",
                "127.0.0.9:19080",
                "--remote",
                "example.test:65009",
                "--ipv4-only",
                "--tun-local",
                "192.0.2.1",
                "--tun-peer",
                "192.0.2.2",
            ])
            .expect("CLI must accept the Windows-compatible flags");
        let runtime = RuntimeConfig::from_matches(&matches);
        assert_eq!(runtime.local, "127.0.0.9:19080");
        assert_eq!(runtime.remote, "example.test:65009");
        assert!(runtime.ipv4_only);
        assert_eq!(runtime.tun_local, "192.0.2.1");
        assert_eq!(runtime.tun_peer, "192.0.2.2");
    }

    #[test]
    fn custom_config_and_cli_follow_the_windows_precedence() {
        let config_path = std::env::temp_dir().join(format!(
            "phantun-client-mac-config-precedence-{}.json",
            std::process::id()
        ));
        fs::write(
            &config_path,
            r#"{
                "local": "127.0.0.7:17080",
                "remote": "configured.example:65007",
                "ipv4_only": true,
                "tun_local": "198.51.100.7",
                "tun_peer": "198.51.100.8",
                "tun_local6": "fd00:7::1",
                "tun_peer6": "fd00:7::2",
                "routes": [{"dest": "203.0.113.0/24", "gateway": "198.51.100.8"}]
            }"#,
        )
        .expect("test config must be writable");

        let matches = command()
            .try_get_matches_from([
                "phantun-client",
                "--config",
                &config_path.to_string_lossy(),
                "--local",
                "127.0.0.8:18080",
                "--tun-peer",
                "198.51.100.9",
            ])
            .expect("CLI must accept the Windows-compatible flags");
        let runtime = RuntimeConfig::from_matches(&matches);
        fs::remove_file(&config_path).expect("test config must be removable");

        assert_eq!(runtime.local, "127.0.0.8:18080");
        assert_eq!(runtime.remote, "configured.example:65007");
        assert!(runtime.ipv4_only);
        assert_eq!(runtime.tun_local, "198.51.100.7");
        assert_eq!(runtime.tun_peer, "198.51.100.9");
        assert_eq!(runtime.tun_local6, "fd00:7::1");
        assert_eq!(runtime.tun_peer6, "fd00:7::2");
        assert_eq!(
            runtime.routes,
            vec![Route {
                dest: "203.0.113.0/24".to_owned(),
                gateway: "198.51.100.8".to_owned(),
            }]
        );
    }

    #[test]
    fn remote_selection_matches_the_windows_ipv4_only_rule() {
        let ipv6: SocketAddr = "[2001:db8::20]:65009".parse().expect("valid IPv6 address");
        let ipv4: SocketAddr = "203.0.113.20:65009".parse().expect("valid IPv4 address");
        assert_eq!(select_remote_address([ipv6, ipv4], false), Some(ipv6));
        assert_eq!(select_remote_address([ipv6, ipv4], true), Some(ipv4));
        assert_eq!(select_remote_address([ipv6], true), None);
    }
}
