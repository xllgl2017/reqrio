mod read;
mod write;
mod flush;
mod shutdown;
mod ext;
mod tcp;
mod tls;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::Sleep;
pub use tcp::TcpStreamA;
pub use tls::{TlsStreamA, TlsStream};
pub use ext::TimeoutRW;

fn poll_sleep<T>(slept: bool, sleep: Pin<&mut Sleep>, cx: &mut Context<'_>, err: impl Fn() -> T) -> Poll<T> {
    if !slept { return Poll::Pending; }
    match sleep.poll(cx) {
        Poll::Ready(_) => Poll::Ready(err()),
        Poll::Pending => Poll::Pending,
    }
}
