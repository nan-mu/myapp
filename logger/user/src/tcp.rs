use anyhow::{bail, Result};
use log::{info, warn};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::{broadcast, mpsc},
};

use crate::config::TcpConfig;

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
    pub async fn start(mut self) -> Result<()> {
        // 初始化tcp客户端
        let socket = TcpSocket::new_v4()?;
        // 太奇怪了tos用32位。rust代码里好像也没溢出检查啊？
        socket.set_tos(self.config.tos as u32)?;
        socket.set_reuseaddr(true)?;
        socket.bind((self.config.logger_ip, self.config.port).into())?;

        // 连接池
        const MAX_CONNECTIONS: usize = 16;
        let listener = socket.listen(MAX_CONNECTIONS as u32)?;
        let (tx, _) = broadcast::channel(MAX_CONNECTIONS);

        let data_length = Arc::new(AtomicUsize::new(0));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        match socket {
                            Ok((mut socket, addr)) => {
                                if tx.receiver_count() >= MAX_CONNECTIONS {
                                    warn!("超过连接池大小, 关闭来自 {addr} 的连接");
                                    socket.shutdown().await.unwrap_or_else(|e| {
                                        warn!("关闭连接失败: {}", e);
                                    });
                                    continue;
                                }else {
                                    info!("TCP连接成功: {}", addr);
                                    tokio::spawn(handle(socket, self.config.size, tx.subscribe(), data_length.clone()));
                                }
                            }
                            Err(e) => {
                                warn!("TCP连接失败: {}", e);
                                continue;
                            }
                        };
                    }
                    _ = self.shutdown.recv() => {
                        info!("TCP工作线程关闭");
                        if let Err(e) = tx.send(()) {
                            warn!("TCP工作线程关闭失败: {}", e);
                        }
                        info!("共计收到 {} 字节数据", data_length.load(Ordering::SeqCst));
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}

async fn handle(
    mut socket: TcpStream,
    max_size: usize,
    mut shutdown: broadcast::Receiver<()>,
    data_counter: Arc<AtomicUsize>,
) -> Result<()> {
    let mut buf = [0; 1024];
    let begin = tokio::time::Instant::now();
    loop {
        tokio::select! {
            readed = socket.read(&mut buf) => {
                match readed {
                    Ok(n) => {if n > max_size {
                        warn!("接收数据 {max_size} 字节，超过最大限制 {n} 字节");
                    }
                    data_counter.fetch_add(n, Ordering::Relaxed);
                    info!("收到 {n} 字节数据：{:02x?}", &buf[..max_size]);},
                    Err(e) => {
                        
                        bail!("读取数据失败: {}", e);
                    }
                }
            },
            _ = shutdown.recv() => {
                info!("连接将关闭, 共计工作 {:#?} 秒", begin.elapsed());
                break;
            }
        }
    }
    Ok(())
}
