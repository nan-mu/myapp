use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use log::debug;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use tokio::task;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Sender};

const FD: Token = Token(0);

pub struct FdHandleBuilder {
    ringbuf: RingBuf<MapData>,
    size: usize,
    events: usize,
}

// struct FdHandler {
//     fd: RingBuf<MapData>,
//     events: Events,
//     poll: mio::Poll,
// }

impl FdHandleBuilder {
    /// Create a new `FdHandleBuilder` with the given file descriptor.
    /// Defaults to readable interest, and 1024 events.
    pub fn new(ringbuf: RingBuf<MapData>, size: usize) -> Result<Self> {
        // 设置fd为非阻塞读写。
        // TODO: 考虑是否暴露上层
        let fd = ringbuf.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
        debug!("fd: {fd} 设置为非阻塞读写");
        Ok(Self {
            ringbuf,
            size,
            events: 1024,
        })
    }
    // /// Wrap Events::with_capacity()
    // fn with_capacity(mut self, capacity: usize) -> Self {
    //     self.events = capacity;
    //     self
    // }
    // fn with_insterests(mut self, interests: Interest) -> Self {
    //     self.interests = interests;
    //     self
    // }
    /// Build the FdHandler
    pub fn start(self) -> Result<(Sender<()>, Arc<AtomicUsize>)> {
        let (tx,mut rx) = mpsc::channel(1);
        let success = Arc::try_from(AtomicUsize::new(0))?;
        let success_return = success.clone();

        let mut ringbuf = self.ringbuf;

        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(self.events);
        let raw_fd = ringbuf.as_raw_fd();
        poll.registry()
            .register(&mut SourceFd(&raw_fd), Token(0), Interest::READABLE)?;

        task::spawn_blocking(move || {
            let success = success.clone();
            if let Err(e) = poll.poll(&mut events, Some(Duration::from_secs(30))){
                debug!("ringbuf poll失败: {}", e);
                return;
            };
            loop {
                for event in &events {
                    if event.token() == FD {
                        if let Some(item) = ringbuf.next(){
                            if item.len() == self.size {
                                success
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }else {
                                debug!("ringbuf数据长度错误: {}", item.len());
                            }
                            drop(item)
                        };

                        // 需要时重新注册事件（EPOLLONESHOT模式下必须）
                        // TODO: 核实是否需要
                        // poll.registry()
                        //     .reregister(&mut SourceFd(&raw_fd), Token(0), Interest::READABLE)
                        //     .unwrap();
                    }
                }

                if let Ok(()) = rx.try_recv() {
                    break;
                }
                match poll.poll(&mut events, Some(Duration::from_secs(5))) {
                    Ok(_) => {
                        if let Ok(()) = rx.try_recv() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("ringbuf等待超时, 接收线程退出: {}", e);
                        break;
                    }
                };
            }
        });
        
        Ok((tx, success_return))
    }
}