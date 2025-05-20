use anyhow::{anyhow, bail};
use std::{
    env,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

use async_trait::async_trait;
use reqwest::Client;
use russh::keys::{load_secret_key, PrivateKey};
use russh::{client, server::Server as _, *};
use serde::{Deserialize, Serialize};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    spawn,
    sync::Mutex,
};

use sshoxy::{Proxy, ProxyHooks};

const DEFAULT_HAAS_API: &str = "https://haas.nic.cz/api";

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    token: String,
    api_url: String,
    socket: Option<SocketAddr>,
    command: Option<PathBuf>,
    ssh_key: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LoadBalancerOutput {
    host: String,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct ValidateInput {
    #[serde(rename = "device-token")]
    device_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ValidateOutput {
    valid: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct HaasPassword {
    pass: String,
    device_token: String,
    remote: String,
    remote_port: u16,
}

impl TryInto<SocketAddr> for LoadBalancerOutput {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<SocketAddr, Self::Error> {
        format!("{}:{}", self.host, self.port)
            .to_socket_addrs()
            .map_err(anyhow::Error::from)?
            .next()
            .ok_or_else(|| anyhow!("wrong load balancer"))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:22".to_socket_addrs().unwrap().next().unwrap(),
            api_url: DEFAULT_HAAS_API.to_owned(),
            token: String::new(),
            socket: None,
            command: None,
            ssh_key: None,
        }
    }
}

fn make_config() -> Result<Config, anyhow::Error> {
    let mut config = Config::default();
    if let Ok(listen) = env::var("HAAS_LISTEN") {
        let listen = listen
            .to_socket_addrs()
            .map_err(anyhow::Error::from)?
            .next()
            .ok_or_else(|| anyhow!("invalid listen"))?;
        config.listen = listen;
    }
    if let Ok(api_url) = env::var("HAAS_API") {
        config.api_url = api_url;
    }
    if let Ok(socket) = env::var("HAAS_SOCKET") {
        let socket = socket
            .to_socket_addrs()
            .map_err(anyhow::Error::from)?
            .next()
            .ok_or_else(|| anyhow!("invalid socket"))?;
        config.socket = Some(socket);
    }
    if let Ok(token) = env::var("HAAS_TOKEN") {
        config.token = token;
    }
    if let Ok(ssh_key) = env::var("HAAS_SECRET_KEY") {
        config.ssh_key = Some(ssh_key.into());
    }
    if let Ok(command) = env::var("HAAS_COMMAND") {
        config.command = Some(command.into());
    }

    Ok(config)
}

fn make_key(config: &Config) -> Result<PrivateKey, anyhow::Error> {
    if let Some(path) = config.ssh_key.as_ref() {
        log::info!("Reading SSH key from '{}'", path.to_string_lossy());
        load_secret_key(&path, None).map_err(anyhow::Error::from)
    } else {
        log::info!("Generating SSH key");
        Ok(PrivateKey::random(
            &mut rand_core::OsRng,
            russh::keys::Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha512),
            },
        )?)
    }
}

#[cfg(feature = "log")]
fn init_logging() {
    env_logger::init();
}

#[cfg(not(feature = "log"))]
fn init_logging() {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    init_logging();

    let config = make_config()?;

    if config.token.is_empty() {
        bail!("token is empty");
    }

    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);

    let server_config = russh::server::Config {
        methods,
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![make_key(&config)?],
        ..Default::default()
    };
    log::debug!("Server config {:#?}", server_config);

    // Get haas address
    let client = Client::new();
    let load_balancer_json: serde_json::Value = client
        .get(format!("{}/honeypot-loadbalancer", config.api_url))
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(anyhow::Error::from)?;
    let load_balancer_output: LoadBalancerOutput =
        serde_json::from_value(load_balancer_json).map_err(anyhow::Error::from)?;
    log::info!(
        "Haas loadbalancer: address {} : port {}",
        load_balancer_output.host,
        load_balancer_output.port
    );

    // Validate haas token using API
    let client = Client::new();
    let validate_output_json: serde_json::Value = client
        .post(format!("{}/validate-token", config.api_url))
        .form(&[("device-token", config.token.clone())])
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(anyhow::Error::from)?;

    let validate_output: ValidateOutput =
        serde_json::from_value(validate_output_json).map_err(anyhow::Error::from)?;

    log::info!("Haas token validation: {}", validate_output.valid);

    if !validate_output.valid {
        bail!("token is not valid")
    }

    let socket_clients = Arc::new(Mutex::new(vec![]));
    if let Some(listener) = config.socket.as_ref() {
        log::info!("Starting push socket: {}", listener);
        let listener = TcpListener::bind(listener)
            .await
            .map_err(anyhow::Error::from)?;

        let socket_clients_cloned = socket_clients.clone();
        spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                socket_clients_cloned
                    .lock()
                    .await
                    .push(Arc::new(Mutex::new(socket)));
            }
            log::error!("Push socket terminated")
        });
    }

    let server_config = Arc::new(server_config);
    let mut sh = Server {
        proxy: Proxy::new(
            ProxyHandler {
                socket_clients,
                socket_enabled: config.socket.is_some(),
                command: config.command,
                token: config.token,
            },
            client::Config::default(),
            load_balancer_output
                .try_into()
                .map_err(anyhow::Error::from)?,
            false,
        ),
    };

    log::info!("Starting proxied ssh server: {}", config.listen);
    sh.run_on_address(server_config, config.listen)
        .await
        .map_err(anyhow::Error::from)
}

#[derive(Clone)]
struct ProxyHandler {
    socket_clients: Arc<Mutex<Vec<Arc<Mutex<TcpStream>>>>>,
    socket_enabled: bool,
    command: Option<PathBuf>,
    token: String,
}

struct Server {
    proxy: Proxy<ProxyHandler>,
}

impl server::Server for Server {
    type Handler = Proxy<ProxyHandler>;
    #[allow(unused_variables)]
    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        self.proxy.clone_with_peer_addr(peer_addr)
    }
}

#[async_trait]
impl server::Handler for ProxyHandler {
    type Error = anyhow::Error;
}

#[async_trait]
impl ProxyHooks for ProxyHandler {
    async fn pre_auth_password(
        &mut self,
        user: String,
        password: String,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> (String, String) {
        let socket_client_guard = self.socket_clients.lock().await;
        let peer_addr_str: String =
            peer_addr.map_or_else(String::new, |e| format!("{}|{}", e.ip(), e.port()));

        // Write to all connected clients
        if self.socket_enabled {
            socket_client_guard.iter().for_each(|socket| {
                let socket_cloned = socket.clone();
                let peer_addr_str = peer_addr_str.clone();
                let password = password.clone();
                let user = user.clone();
                spawn(async move {
                    let mut guard = socket_cloned.lock().await;
                    if guard
                        .write(format!("{}|{}|{}\n", peer_addr_str, user, password).as_bytes())
                        .await
                        .is_ok()
                    {
                        let _ = guard.flush().await;
                    }
                });
            });
        }

        if let Some(command) = self.command.as_ref() {
            if let Err(_) = Command::new(command)
                .args(&[peer_addr_str.as_str(), user.as_str(), password.as_str()])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .env_clear()
                .spawn()
            {
                log::warn!("Failed to start command '{}'", command.to_string_lossy());
            }
        }

        let password = if let Some(peer_addr) = peer_addr {
            serde_json::to_string(&HaasPassword {
                pass: password,
                remote: peer_addr.ip().to_string(),
                remote_port: peer_addr.port(),
                device_token: self.token.clone(),
            })
            .unwrap()
        } else {
            password
        };

        (user, password)
    }
}
