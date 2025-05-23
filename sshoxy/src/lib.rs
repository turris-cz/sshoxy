use async_trait::async_trait;
use russh::server::{Msg, Session};
use russh::*;
use russh::{MethodKind, MethodSet};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

/// Deals with connection from proxy to ssh server
#[derive(Clone)]
struct SshServerHandler {
    propagate_channel_failure: bool,
    /// ssh client's channel to ssh server
    /// is used to send data from ssh server back to client
    client_writer: Arc<Mutex<Option<ChannelWriteHalf<Msg>>>>,
    client_session_handle: Arc<Mutex<Option<server::Handle>>>,
}

impl client::Handler for SshServerHandler {
    type Error = russh::Error;

    #[allow(unused_variables)]
    async fn channel_success(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!("SSH server client: channel success (id={})", channel);
        // Get channel id of connected client
        let channel_id = self.client_writer.lock().await.as_ref().unwrap().id();
        self.client_session_handle
            .lock()
            .await
            .as_ref()
            .unwrap()
            .channel_success(channel_id)
            .await
            .map_err(|e| Error::Disconnect)
    }

    #[allow(unused_variables)]
    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!("SSH server client: channel failure (id={})", channel);
        if self.propagate_channel_failure {
            // Get channel id of connected client
            let channel_id = self.client_writer.lock().await.as_ref().unwrap().id();
            self.client_session_handle
                .lock()
                .await
                .as_ref()
                .unwrap()
                .channel_failure(channel_id)
                .await
                .map_err(|e| Error::Disconnect)
        } else {
            Ok(())
        }
    }

    #[allow(unused_variables)]
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!(
            "SSH server client: got extended data (size={}) (id={})",
            data.len(),
            channel
        );
        self.client_writer
            .lock()
            .await
            .as_ref()
            .unwrap()
            .extended_data(ext, data)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        log::debug!(
            "SSH server client: got data (size={}) (id={})",
            data.len(),
            channel
        );
        self.client_writer
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
        server_public_key: &russh::keys::PublicKey,
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
        log::debug!("SSH server client: channel close (id={})", channel);
        self.client_writer
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
        log::debug!("SSH server client: channel eof (id={})", channel);
        self.client_writer
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
        log::debug!(
            "SSH server client: exit status {} (id={})",
            exit_status,
            channel
        );
        // Get channel id of connected client
        let channel_id = self.client_writer.lock().await.as_ref().unwrap().id();
        self.client_session_handle
            .lock()
            .await
            .as_ref()
            .unwrap()
            .exit_status_request(channel_id, exit_status)
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
        peer_addr: Option<SocketAddr>,
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
    propagate_channel_failure: bool,
    peer_addr: Option<std::net::SocketAddr>,
    client_writer: Arc<Mutex<Option<ChannelWriteHalf<Msg>>>>,
    client_session_handle: Arc<Mutex<Option<server::Handle>>>,
    server_writer: Arc<Mutex<Option<ChannelWriteHalf<client::Msg>>>>,
    server_config: Arc<russh::client::Config>,
    server_addr: SocketAddr,
    id: usize,
}

impl<T> Clone for Proxy<T>
where
    T: server::Handler + Clone,
{
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            propagate_channel_failure: self.propagate_channel_failure,
            peer_addr: None,
            client_writer: Arc::new(Mutex::new(None)),
            client_session_handle: Arc::new(Mutex::new(None)),
            server_writer: Arc::new(Mutex::new(None)),
            server_config: self.server_config.clone(),
            server_addr: self.server_addr.clone(),
            id: self.id + 1,
        }
    }
}

impl<T> Proxy<T>
where
    T: server::Handler + Clone,
{
    /// Creates new Proxy instance
    pub fn new(
        handler: T,
        server_config: russh::client::Config,
        server_addr: SocketAddr,
        propagate_channel_failure: bool,
    ) -> Self {
        Self {
            handler,
            peer_addr: None,
            propagate_channel_failure,
            client_writer: Arc::new(Mutex::new(None)),
            client_session_handle: Arc::new(Mutex::new(None)),
            server_writer: Arc::new(Mutex::new(None)),
            server_config: Arc::new(server_config),
            server_addr,
            id: 0,
        }
    }

    /// Clones with new client
    pub fn clone_with_peer_addr(&self, peer_addr: Option<SocketAddr>) -> Self {
        let mut cloned = self.clone();
        cloned.peer_addr = peer_addr;
        cloned
    }
}

impl<T> server::Handler for Proxy<T>
where
    T: ProxyHooks + Send + Clone,
{
    type Error = T::Error;

    #[allow(unused_variables)]
    async fn auth_keyboard_interactive<'a>(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        log::debug!("Connected client: auth_keyboard_interactive");
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::Password);
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(methods),
            partial_success: false,
        })
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        log::debug!("Connected client: auth_succeeded");
        *self.client_session_handle.lock().await = Some(session.handle());
        Ok(())
    }

    #[allow(unused_variables)]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        log::debug!("Connected client: auth_publickey");
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::Password);
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(methods),
            partial_success: false,
        })
    }

    #[allow(unused_variables)]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        log::debug!("Connected client: open_session (id={})", channel.id());
        let (mut reader, writer) = channel.split();
        *self.client_writer.lock().await = Some(writer);

        // we need to read the channel otherwise messages got stuck
        // when channel_buffer_size is reached
        tokio::spawn(async move { while let Some(_msg) = reader.wait().await {} });

        Ok(true)
    }

    #[allow(unused_variables)]
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        log::debug!("Connected client: auth_password");
        let (user, password) = self
            .handler
            .pre_auth_password(user.to_owned(), password.to_owned(), self.peer_addr.clone())
            .await;

        // share proxy->client structs
        let client_channel = Arc::new(Mutex::new(None));
        let client_session_handle = Arc::new(Mutex::new(None));
        let mut server_handle = client::connect(
            self.server_config.clone(),
            self.server_addr.clone(),
            SshServerHandler {
                propagate_channel_failure: self.propagate_channel_failure,
                client_writer: client_channel.clone(),
                client_session_handle: client_session_handle.clone(),
            },
        )
        .await?;
        server_handle.authenticate_password(user, password).await?;
        let channel = server_handle.channel_open_session().await?;

        self.client_writer = client_channel;
        self.client_session_handle = client_session_handle;

        let (mut reader, writer) = channel.split();
        *self.server_writer.lock().await = Some(writer);

        // we need to read the channel otherwise messages got stuck
        // when channel_buffer_size is reached
        tokio::spawn(async move { while let Some(_msg) = reader.wait().await {} });

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
        log::debug!("Connected client: pty_request (id={})", channel);
        self.server_writer
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
        log::debug!("Connected client: shell_request (id={})", channel);
        self.server_writer
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
        log::debug!("Connected client: env_request (id={})", channel);
        self.server_writer
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
        log::debug!(
            "Connected client: got data (size={}) (id={})",
            data.len(),
            channel
        );
        let guard = self.server_writer.lock().await;
        guard.as_ref().unwrap().data(data).await.map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::debug!(
            "Connected client: got extended data (size={}) (id={})",
            data.len(),
            channel
        );
        self.server_writer
            .lock()
            .await
            .as_ref()
            .unwrap()
            .extended_data(code, data)
            .await
            .map_err(Into::into)
    }

    #[allow(unused_variables)]
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::debug!("Connected client: channel_close (id={})", channel);
        self.server_writer
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
        log::debug!("Connected client: channel_eof (id={})", channel);
        self.server_writer
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
        log::debug!("Connected client: exec_request (id={})", channel);
        self.server_writer
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
        log::debug!("Connected client: window change request (id={})", channel);
        self.server_writer
            .lock()
            .await
            .as_ref()
            .unwrap()
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(Into::into)
    }
}
