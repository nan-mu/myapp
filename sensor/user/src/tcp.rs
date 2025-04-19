use anyhow::Result;
use log::{info, warn};
use std::time::Duration;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpSocket, TcpStream},
    sync::mpsc,
    time::interval,
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
    pub async fn start(self) -> Result<()> {
        // 初始化tcp客户端
        let socket = TcpSocket::new_v4()?;
        // 太奇怪了tos用32位。rust代码里好像也没溢出检查啊？
        socket.set_tos(self.config.tos as u32)?;
        let mut socket = socket
            .connect((self.config.target_ip, self.config.port).into())
            .await?;
        let period = Duration::from_millis((1000.0 / self.config.freq) as u64);
        let mut interval = interval(period);
        info!(
            "TCP连接成功, 目标IP: {}, 端口: {}, 间隔: {interval:?}. 开始传输数据",
            self.config.target_ip, self.config.port
        );
        let mut shutdown = self.shutdown;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        handle(&mut socket, self.config.size).await.unwrap_or_else(|e| {
                            warn!("TCP数据传输失败: {}", e);
                        });
                    }
                    _ = shutdown.recv() => {
                        info!("TCP工作线程关闭");
                        socket.shutdown().await.unwrap_or_else(|e| {
                            warn!("TCP关闭失败: {}", e);
                        });
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}

async fn handle(socket: &mut TcpStream, size: usize) -> Result<()> {
    socket.write_all(&vec![0xaa; size]).await?;
    socket.flush().await?;
    Ok(())
}
