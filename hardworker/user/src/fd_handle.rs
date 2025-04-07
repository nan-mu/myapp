use std::borrow::Borrow;
use std::os::fd::AsRawFd;
use anyhow::Result;
use aya::maps::{RingBuf, MapData};
use mio::{Events, Interest, Token};

const FD: Token = Token(0);

struct FdHandleBuilder<T> {
    fd: RingBuf<T>,
    poll: mio::Poll,
    events: usize,
    interests: Interest,
}

struct FdHandler<T> {
    fd: RingBuf<T>,
    events: Events,
    poll: mio::Poll,
}

impl<T: Borrow<MapData>> FdHandleBuilder<T> {
    /// Create a new `FdHandleBuilder` with the given file descriptor.
    /// Defaults to readable interest, and 1024 events.
    fn new(fd: RingBuf<T>) -> Result<Self> {
        let poll = mio::Poll::new()?;
        Ok(Self {
            fd,
            poll,
            interests: Interest::READABLE,
            events: 1024,
        })
    }
    /// Wrap Events::with_capacity()
    fn with_capacity(mut self, capacity: usize) -> Self {
        self.events = capacity;
        self
    }
    fn with_insterests(mut self, interests: Interest) -> Self {
        self.interests = interests;
        self
    }
    /// Build the FdHandler
    fn build(self) -> Result<FdHandler<T>> {
        let events = Events::with_capacity(self.events);
        let fd = self.fd.as_raw_fd();
        let mut source = mio::unix::SourceFd(&fd);

        self.poll
            .registry()
            .register(&mut source, FD, self.interests);

        Ok(FdHandler {
            fd: self.fd,
            events,
            poll: self.poll,
        })
    }
}
