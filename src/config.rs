use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    pub secret_key: String,
    pub admin_username: String,
    /// 已哈希的管理员密码；首次启动若库中无用户则写入
    pub admin_password_hash: String,
    pub admin_password_plain_for_bootstrap: Option<String>,
    pub worker_concurrency: usize,
    pub log_retention_days: i64,
}

#[derive(Debug, Deserialize)]
struct EnvFile {
    #[serde(default = "default_secret")]
    secret_key: String,
    #[serde(default = "default_admin_user")]
    admin_username: String,
    #[serde(default = "default_admin_pass")]
    admin_password: String,
    #[serde(default = "default_concurrency")]
    worker_concurrency: usize,
    #[serde(default = "default_retention")]
    log_retention_days: i64,
}

fn default_secret() -> String {
    "change-me".into()
}
fn default_admin_user() -> String {
    "admin".into()
}
fn default_admin_pass() -> String {
    "admin".into()
}
fn default_concurrency() -> usize {
    4
}
fn default_retention() -> i64 {
    30
}

impl AppConfig {
    pub fn load(data_dir_override: Option<PathBuf>) -> Result<Self> {
        let data_dir = data_dir_override.unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("deploy_online")
        });

        // 可选 .env：优先 data_dir/.env，其次当前目录
        let env_path = data_dir.join(".env");
        if env_path.exists() {
            dotenvy::from_path(&env_path).ok();
        } else {
            dotenvy::dotenv().ok();
        }

        let secret_key = std::env::var("SECRET_KEY").unwrap_or_else(|_| "change-me".into());
        let admin_username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
        let admin_password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".into());
        let worker_concurrency = std::env::var("WORKER_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4);
        let log_retention_days = std::env::var("LOG_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        if secret_key == "change-me" || secret_key.len() < 16 {
            bail!("请设置 SECRET_KEY（至少 16 字符的随机串），例如环境变量或 {}/.env", data_dir.display());
        }
        if admin_password == "admin" {
            bail!("请设置 ADMIN_PASSWORD（不要使用默认值 admin）");
        }

        let admin_password_hash = crate::db::hash_password(&admin_password)?;

        Ok(Self {
            data_dir,
            secret_key,
            admin_username,
            admin_password_hash,
            admin_password_plain_for_bootstrap: Some(admin_password),
            worker_concurrency: worker_concurrency.max(1),
            log_retention_days,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("创建数据目录失败: {}", self.data_dir.display()))?;
        std::fs::create_dir_all(self.data_dir.join("projects")).ok();
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("deploy_online.db")
    }
}
