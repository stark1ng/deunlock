//! Own one replaceable notification session without changing GATT registration.
//! BUG-20261018-1736: closure is observed before the next authentication request.

use std::{io, sync::Arc};

use async_trait::async_trait;
use bluer::gatt::local::CharacteristicNotifier;
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use tokio::sync::Mutex;

#[async_trait]
pub(super) trait NotificationSink: Send + Sync {
    async fn send(&self, frame: &[u8]) -> io::Result<()>;
    async fn closed(&self) -> io::Result<()>;
}

pub(super) struct DbusNotifier {
    notifier: Mutex<CharacteristicNotifier>,
    stopped: Shared<BoxFuture<'static, ()>>,
}

impl DbusNotifier {
    pub(super) fn new(notifier: CharacteristicNotifier) -> Self {
        let stopped = notifier.stopped().boxed().shared();
        Self {
            notifier: Mutex::new(notifier),
            stopped,
        }
    }
}

#[async_trait]
impl NotificationSink for DbusNotifier {
    async fn send(&self, frame: &[u8]) -> io::Result<()> {
        self.notifier.lock().await.notify(frame.to_vec()).await.map_err(io::Error::other)
    }

    async fn closed(&self) -> io::Result<()> {
        self.stopped.clone().await;
        Ok(())
    }
}

/// The radio boundary permits socket-backed lifecycle tests without BlueZ.
#[derive(Default)]
pub(super) struct NotificationChannel(Mutex<Option<Arc<dyn NotificationSink>>>);

impl NotificationChannel {
    /// Cancellation-safe: the control loop restarts this wait after each event.
    pub(super) async fn wait_closed(&self) -> io::Result<()> {
        let Some(writer) = self.0.lock().await.clone() else {
            return std::future::pending().await;
        };
        let result = writer.closed().await;
        self.clear_if_current(&writer).await;
        result
    }

    async fn clear_if_current(&self, writer: &Arc<dyn NotificationSink>) {
        let mut current = self.0.lock().await;
        if current.as_ref().is_some_and(|active| Arc::ptr_eq(active, writer)) {
            *current = None;
        }
    }

    pub(super) async fn install(&self, writer: Arc<dyn NotificationSink>) {
        *self.0.lock().await = Some(writer);
    }

    pub(super) async fn send(&self, frame: &[u8]) -> io::Result<()> {
        let writer = self.0.lock().await.clone().ok_or(io::ErrorKind::NotConnected)?;
        let result = writer.send(frame).await;
        if result.is_err() {
            self.clear_if_current(&writer).await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncReadExt, net::UnixStream};

    use super::*;

    struct WireSink(UnixStream);

    #[async_trait]
    impl NotificationSink for WireSink {
        async fn closed(&self) -> io::Result<()> {
            self.0.readable().await
        }

        async fn send(&self, frame: &[u8]) -> io::Result<()> {
            self.0.writable().await?;
            match self.0.try_write(frame)? {
                n if n == frame.len() => Ok(()),
                _ => Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }

    #[tokio::test]
    async fn a_failed_send_discards_the_failed_session() {
        let channel = NotificationChannel::default();
        let (writer, peer) = UnixStream::pair().unwrap();
        channel.install(Arc::new(WireSink(writer))).await;
        drop(peer);
        assert!(channel.send(b"challenge").await.is_err());
        assert_eq!(channel.send(b"challenge").await.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn an_old_session_closing_does_not_clear_its_replacement() {
        let channel = NotificationChannel::default();
        let (old, old_peer) = UnixStream::pair().unwrap();
        channel.install(Arc::new(WireSink(old))).await;
        let closing = channel.wait_closed();
        tokio::pin!(closing);
        assert!(futures::poll!(&mut closing).is_pending());
        let (new, mut peer) = UnixStream::pair().unwrap();
        channel.install(Arc::new(WireSink(new))).await;
        drop(old_peer);
        closing.await.unwrap();
        channel.send(b"challenge").await.unwrap();
        let mut received = [0; 9];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"challenge");
    }

    #[tokio::test]
    async fn closure_is_handled_before_a_challenge_is_sent() {
        let channel = NotificationChannel::default();
        let (writer, peer) = UnixStream::pair().unwrap();
        channel.install(Arc::new(WireSink(writer))).await;
        drop(peer);
        channel.wait_closed().await.unwrap();
        assert_eq!(channel.send(b"challenge").await.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn subscribed_channel_sends_the_frame_over_the_owned_socket() {
        let channel = NotificationChannel::default();
        let (writer, mut peer) = UnixStream::pair().unwrap();
        channel.install(Arc::new(WireSink(writer))).await;
        channel.send(b"challenge").await.unwrap();
        let mut received = [0; 9];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"challenge");
    }

    #[tokio::test]
    async fn an_unsubscribed_channel_cannot_send() {
        let channel = NotificationChannel::default();
        assert_eq!(
            channel.send(b"challenge").await.unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
    }

    #[tokio::test]
    async fn waiting_on_an_unsubscribed_channel_does_not_spin() {
        let channel = NotificationChannel::default();
        let closed = channel.wait_closed();
        tokio::pin!(closed);
        assert!(futures::poll!(&mut closed).is_pending());
    }
}
