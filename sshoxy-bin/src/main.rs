use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use russh::keys::{load_secret_key, signature::rand_core::OsRng, PrivateKey};
use russh::{client, server::Server as _, *};

use clap::Parser;

/// Simple ssh proxy
#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "Acts as SSH server which forwards its requests to another SSH server"
)]
struct Args {
    /// Path where to look for private server key
    /// If no certificate is provided RSA(2048) will be generated
    /// each time when program starts
    #[arg(short, long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Address and port where the proxy will listen to
    #[arg(
        short,
        long,
        value_name = "IP:PORT",
        default_value_t = SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, 1).into(), 2222)
        )
    ]
    listen: SocketAddr,

    /// Address and port of SSH server which will be proxied
    #[arg(short, long, value_name = "IP:PORT")]
    ssh_server: SocketAddr,
}

use sshoxy::{Proxy, ProxyHooks};

fn make_key(args: &Args) -> Result<PrivateKey, i32> {
    if let Some(path) = args.key_file.as_ref() {
        log::info!("Reading SSH key from '{}'", path.to_string_lossy());
        Ok(load_secret_key(&path, None).map_err(|_| 1)?)
    } else {
        log::info!("Generating SSH key");
        Ok(
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Rsa { hash: None })
                .map_err(|_| 1)?,
        )
    }
}

#[tokio::main]
async fn main() -> Result<(), i32> {
    let args = Args::parse();
    env_logger::init();

    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);

    let config = russh::server::Config {
        methods,
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![make_key(&args)?],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        proxy: Proxy::new(
            ProxyHandler {},
            client::Config::default(),
            args.ssh_server,
            false,
        ),
    };

    sh.run_on_address(config, args.listen)
        .await
        .map_err(|e| e.raw_os_error().unwrap_or(1))
}

#[derive(Clone)]
struct ProxyHandler {}

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
        let peer_str = peer_addr.map_or_else(String::new, |e| e.to_string());
        log::info!("User {} is trying to authenticate from {}", user, peer_str);
        (user, password)
    }
}
