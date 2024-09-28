use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Msg, Session};
use russh::*;
use tokio::sync::Mutex;

/// Deals with connection from proxy to ssh server
#[derive(Clone)]
struct SshServerHandler {
    /// ssh client's channel to ssh server
    /// is used to send data from ssh server back to client
    client_channel: Arc<Mutex<Option<Channel<Msg>>>>,
    client_session_handle: Arc<Mutex<Option<server::Handle>>>,
}

#[async_trait]
impl client::Handler for SshServerHandler {
    type Error = russh::Error;

    #[allow(unused_variables)]
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.client_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .data(data)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // bypass server key checking
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.client_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .close()
            .await
    }

    #[allow(unused_variables)]
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.client_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .eof()
            .await
    }

    #[allow(unused_variables)]
    async fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.client_session_handle
            .lock()
            .await
            .as_ref()
            .unwrap()
            .exit_status_request(channel, exit_status)
            .await
            .map_err(|_| Error::Disconnect)
    }
}

#[async_trait]
/// All functions in this trait could be overriden by client library
pub trait ProxyHooks: server::Handler {
    /// Function is triggered in auth_password
    /// and can be used to override password or username
    /// before authentication attempt to Ssh server is made
    #[allow(unused_variables)]
    async fn pre_auth_password(
        &mut self,
        user: String,
        password: String,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> (String, String) {
        (user, password)
    }
}

/// Main structure representing proxy
///
/// Ssh server function of the proxy are implemented here
pub struct Proxy<T>
where
    T: server::Handler + Clone,
{
    handler: T,
    peer_addr: Option<std::net::SocketAddr>,
    client_channel: Arc<Mutex<Option<Channel<Msg>>>>,
    client_session_handle: Arc<Mutex<Option<server::Handle>>>,
    server_channel: Arc<Mutex<Option<Channel<client::Msg>>>>,
    server_config: Arc<russh::client::Config>,
    id: usize,
}

impl<T> Clone for Proxy<T>
where
    T: server::Handler + Clone,
{
    fn clone(&self) -> Self {
        Self {
            peer_addr: None,
            handler: self.handler.clone(),
            client_channel: Arc::new(Mutex::new(None)),
            client_session_handle: Arc::new(Mutex::new(None)),
            server_channel: Arc::new(Mutex::new(None)),
            server_config: self.server_config.clone(),
            id: self.id + 1,
        }
    }
}

impl<T> Proxy<T>
where
    T: server::Handler + Clone,
{
    /// Creates new Proxy instance
    pub fn new(handler: T, server_config: russh::client::Config) -> Self {
        Self {
            handler,
            peer_addr: None,
            client_channel: Arc::new(Mutex::new(None)),
            client_session_handle: Arc::new(Mutex::new(None)),
            server_channel: Arc::new(Mutex::new(None)),
            server_config: Arc::new(server_config),
            id: 0,
        }
    }

    /// Clones with new client
    pub fn clone_with_peer_addr(&self, peer_addr: Option<std::net::SocketAddr>) -> Self {
        let mut cloned = self.clone();
        cloned.peer_addr = peer_addr;
        cloned
    }
}

#[async_trait]
impl<T> server::Handler for Proxy<T>
where
    T: ProxyHooks + Send + Clone,
{
    type Error = T::Error;

    #[allow(unused_variables)]
    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<server::Response<'async_trait>>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(MethodSet::PASSWORD),
        })
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        *self.client_session_handle.lock().await = Some(session.handle());
        Ok(())
    }

    #[allow(unused_variables)]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &keys::key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(MethodSet::PASSWORD),
        })
    }

    #[allow(unused_variables)]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        *self.client_channel.lock().await = Some(channel);
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        let (user, password) = self
            .handler
            .pre_auth_password(user.to_owned(), password.to_owned(), self.peer_addr.clone())
            .await;

        // share proxy->client structs
        let client_channel = Arc::new(Mutex::new(None));
        let client_session_handle = Arc::new(Mutex::new(None));
        let mut server_handle = client::connect(
            self.server_config.clone(),
            "127.0.0.1:22",
            SshServerHandler {
                client_channel: client_channel.clone(),
                client_session_handle: client_session_handle.clone(),
            },
        )
        .await?;
        server_handle.authenticate_password(user, password).await?;
        let channel = server_handle.channel_open_session().await?;

        self.client_channel = client_channel;
        self.client_session_handle = client_session_handle;

        *self.server_channel.lock().await = Some(channel);

        Ok(server::Auth::Accept)
    }

    #[allow(unused_variables)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .request_shell(true)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .set_env(true, variable_name, variable_value)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .data(data)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .close()
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .eof()
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .exec(true, data)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.server_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(Into::into)
    }
}
