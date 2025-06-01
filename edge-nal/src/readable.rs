use core::task::{Context, Poll};

use embedded_io_async::ErrorType;

pub trait Readable: ErrorType {
    async fn readable(&mut self) -> Result<(), Self::Error>;
}

pub trait PollReadable: ErrorType {
    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}

impl<T> Readable for &mut T
where
    T: Readable,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
        (**self).readable().await
    }
}
