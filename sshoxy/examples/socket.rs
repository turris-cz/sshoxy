use std::sync::Arc;

use async_trait::async_trait;
use russh::{client, server::Server as _, *};
use russh_keys::key;

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    spawn,
    sync::Mutex,
};

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

    let listener = TcpListener::bind("127.0.0.1:8888")
        .await
        .map_err(|e| e.raw_os_error().unwrap_or(1))?;

    let socket_clients = Arc::new(Mutex::new(vec![]));

    let socket_clients_cloned = socket_clients.clone();
    spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            socket_clients_cloned
                .lock()
                .await
                .push(Arc::new(Mutex::new(socket)));
        }
    });

    let config = Arc::new(config);
    let mut sh = Server {
        proxy: Proxy::new(ProxyHandler { socket_clients }, client::Config::default()),
    };

    sh.run_on_address(config, ("127.1.0.1", 2222))
        .await
        .map_err(|e| e.raw_os_error().unwrap_or(1))
}

#[derive(Clone)]
struct ProxyHandler {
    socket_clients: Arc<Mutex<Vec<Arc<Mutex<TcpStream>>>>>,
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
        let peer_addr: String = peer_addr.map_or_else(String::new, |e| e.to_string());

        // Write to all connected clients
        socket_client_guard.iter().for_each(|socket| {
            let socket_cloned = socket.clone();
            let peer_addr = peer_addr.clone();
            let password = password.clone();
            let user = user.clone();
            spawn(async move {
                let mut guard = socket_cloned.lock().await;
                if guard
                    .write(format!("{}|{}|{}\n", peer_addr, user, password).as_bytes())
                    .await
                    .is_ok()
                {
                    let _ = guard.flush().await;
                }
            });
        });
        (user, password)
    }
}
