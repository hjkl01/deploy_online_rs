mod api;
mod config;
mod crypto;
mod db;
mod embed;
mod workflow;
mod worker;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::db::Db;
use crate::worker::Worker;

#[derive(Parser, Debug)]
#[command(name = "deploy_online", about = "单二进制 Linux 部署平台（YAML 工作流）")]
struct Cli {
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1:8000", env = "DEPLOY_ONLINE_BIND")]
    bind: String,

    /// 数据目录（SQLite、密钥等）
    #[arg(long, env = "DEPLOY_ONLINE_DATA")]
    data_dir: Option<PathBuf>,

    /// 仅执行一次指定项目部署后退出（CI / 脚本用）
    #[arg(long)]
    run: Option<String>,

    /// 从 YAML 文件导入项目
    #[arg(long)]
    import: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = AppConfig::load(cli.data_dir)?;
    cfg.ensure_dirs()?;

    let db = Db::open(&cfg.db_path())?;
    db.migrate()?;
    db.ensure_admin(&cfg.admin_username, &cfg.admin_password_hash)?;

    if let Some(path) = cli.import {
        let yaml = std::fs::read_to_string(&path)?;
        let name = db.import_project_yaml(&yaml)?;
        tracing::info!("已导入项目: {}", name);
        return Ok(());
    }

    if let Some(name) = cli.run {
        let id = db.create_deployment_by_name(&name, None)?;
        tracing::info!("开始部署 #{} project={}", id, name);
        worker::run_one(&db, id, &cfg.secret_key).await?;
        return Ok(());
    }

    let db = Arc::new(db);
    let worker_handle = Worker::spawn(Arc::clone(&db), cfg.worker_concurrency, cfg.secret_key.clone());

    // 启动时清理过期日志
    match db.purge_old_logs(cfg.log_retention_days) {
        Ok(n) if n > 0 => tracing::info!("已清理 {n} 条过期日志"),
        Ok(_) => {}
        Err(e) => tracing::warn!("清理日志失败: {e:#}"),
    }

    let app = api::router(Arc::clone(&db), cfg.clone());
    let addr: SocketAddr = cli.bind.parse()?;
    tracing::info!("deploy_online 监听 http://{}", addr);
    tracing::info!("数据目录: {}", cfg.data_dir.display());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    worker_handle.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("收到停止信号，正在退出…");
}
