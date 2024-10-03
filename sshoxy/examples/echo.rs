use std::sync::Arc;

use async_trait::async_trait;
use russh::{client, server::Server as _, *};
use russh_keys::key;

use sshoxy::{Proxy, ProxyHooks};

#[tokio::main]
async fn main() -> Result<(), i32> {
    env_logger::init();

    let config = russh::server::Config {
        methods: MethodSet::PASSWORD,
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key::KeyPair::generate_rsa(2048, key::SignatureHash::SHA2_512).unwrap()],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        proxy: Proxy::new(
            ProxyHandler {},
            client::Config::default(),
            "127.0.0.1:22".parse().unwrap(),
        ),
    };

    sh.run_on_address(config, ("127.1.0.1", 2222))
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
        println!("Username: {}", user);
        println!("Password: {:?}", password);
        println!(
            "Peer: {:?}",
            peer_addr.map_or_else(String::new, |e| e.to_string())
        );
        (user, password)
    }
}
