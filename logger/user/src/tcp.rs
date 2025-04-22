use anyhow::{Context, Result};
use log::debug;
use mio::{
    event::Source,
    net::{TcpListener, TcpStream},
    Interest, Poll, Token,
};
use nix::{
    fcntl::{fcntl, FcntlArg, OFlag},
    sys::socket::{setsockopt, sockopt::IpTos},
};
use std::{
    collections::HashMap, io::Read, os::fd::{AsFd, AsRawFd}, sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    }, time::Duration, vec
};
use tokio::{sync::mpsc, task};

use crate::config::TcpConfig;

const SERVER: Token = Token(0);

#[derive(Debug)]
pub struct TcpHandler {
    config: TcpConfig,
    signal: mpsc::Sender<()>,
    shutdown: mpsc::Receiver<()>,
}

impl From<TcpConfig> for TcpHandler {
    fn from(value: TcpConfig) -> Self {
        let (tx, rx) = mpsc::channel(1);
        TcpHandler {
            config: value,
            signal: tx,
            shutdown: rx,
        }
    }
}

impl TcpHandler {
    pub fn get_signal(&self) -> mpsc::Sender<()> {
        self.signal.clone()
    }

    /// 启动TCP工作线程
    pub async fn start(mut self) -> Result<(Arc<AtomicUsize>, Arc<AtomicUsize>)> {
        let mut listener = TcpListener::bind((self.config.host_ip, self.config.port).into())?;
        let fd = listener.as_fd();

        // 设置 tos
        setsockopt(&fd, IpTos, &(self.config.tos as i32)).context("设置套接字tos失败")?;

        // 设置非阻塞
        let flags = OFlag::from_bits_truncate(fcntl(fd.as_raw_fd(), FcntlArg::F_GETFL).unwrap());
        fcntl(fd.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();

        // 记录匹配数据长度成功和失败的次数
        let success = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicUsize::new(0));
        let result = (success.clone(), fail.clone());
        // tcp会话计数
        let mut counter = 0;
        let mut sockets: HashMap<Token, TcpStream> = HashMap::new();
        // 缓冲区
        let mut buffer = vec![0; self.config.mtu];

        let mut poll = Poll::new()?;
        let mut events = mio::Events::with_capacity(1024);
        poll.registry()
            .register(&mut listener, SERVER, Interest::READABLE)?;

        task::spawn_blocking(move || {
            loop {
                for event in events.iter() {
                    match event.token() {
                        SERVER => loop {
                            // 连接建立分支
                            match listener.accept() {
                                Ok((mut socket, _)) => {
                                    counter += 1;
                                    let token = Token(counter);
                                    socket
                                        .register(poll.registry(), token, Interest::READABLE)
                                        .unwrap();
                                    sockets.insert(token, socket);
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => break,
                            }
                        },
                        token if event.is_readable() => {
                            // 会话可读的分支
                            loop {
                                let read = sockets.get_mut(&token).unwrap().read(&mut buffer);
                                match read {
                                    Ok(0) => {
                                        debug!("连接关闭");
                                        sockets.remove(&token);
                                        break;
                                    }
                                    Ok(n) => {
                                        if n == self.config.size {
                                            success.fetch_add(n, Ordering::SeqCst);
                                        } else {
                                            fail.fetch_add(n, Ordering::SeqCst);
                                        }
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        break
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if let Ok(()) = self.shutdown.try_recv() {
                    break;
                }
                match poll.poll(&mut events, Some(Duration::from_secs(5))) {
                    Ok(_) => {
                        if let Ok(()) = self.shutdown.try_recv() {
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

        Ok(result)
    }
}
