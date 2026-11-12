//! 部署执行：git sync + 可配置 shell 步骤

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
#[cfg(unix)]
use tokio::sync::watch;

use crate::db::Db;
use crate::workflow::{assert_under_home, ProjectWorkflow, StepKind};

pub struct Worker {
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl Worker {
    pub fn spawn(db: Arc<Db>, concurrency: usize, secret_key: String) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = tokio::spawn(async move {
            if let Err(e) = run_loop(db, concurrency, secret_key, shutdown_rx).await {
                tracing::error!("Worker 退出: {e:#}");
            }
        });
        Self { shutdown_tx, join }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join.await;
    }
}

async fn run_loop(
    db: Arc<Db>,
    concurrency: usize,
    secret_key: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    db.recover_stale()?;
    let mut active: HashMap<i64, tokio::task::JoinHandle<()>> = HashMap::new();

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        // 回收完成任务
        active.retain(|_, h| !h.is_finished());

        let capacity = concurrency.saturating_sub(active.len());
        if capacity > 0 {
            let exclude: Vec<i64> = active.keys().copied().collect();
            match db.claim_pending(&exclude, capacity) {
                Ok(claimed) => {
                    for (job_id, project_id) in claimed {
                        let db2 = Arc::clone(&db);
                        let sk = secret_key.clone();
                        let handle = tokio::spawn(async move {
                            if let Err(e) = execute_deployment(&db2, job_id, &sk).await {
                                tracing::error!("部署 #{job_id} 异常: {e:#}");
                                let _ = db2.finish_deployment(job_id, "failed", 1);
                            }
                        });
                        active.insert(project_id, handle);
                    }
                }
                Err(e) => tracing::warn!("领取任务失败: {e:#}"),
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(if active.is_empty() { 1000 } else { 200 })) => {},
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    tracing::info!("Worker 停止领取，等待 {} 个任务", active.len());
    let timeout = Duration::from_secs(30);
    let wait = async {
        for (_, h) in active {
            let _ = h.await;
        }
    };
    let _ = tokio::time::timeout(timeout, wait).await;
    Ok(())
}

/// CLI `--run` 单次执行
pub async fn run_one(db: &Db, deployment_id: i64, secret_key: &str) -> Result<()> {
    // 标记 running
    {
        let c = db.conn()?;
        let now = chrono::Utc::now().to_rfc3339();
        c.execute(
            "UPDATE deployments SET status = 'running', started_at = ?1 WHERE id = ?2",
            rusqlite::params![now, deployment_id],
        )?;
    }
    execute_deployment(db, deployment_id, secret_key).await
}

async fn execute_deployment(db: &Db, deployment_id: i64, secret_key: &str) -> Result<()> {
    let job = db
        .get_deployment(deployment_id)?
        .context("部署记录不存在")?;
    let wf = ProjectWorkflow::parse(&job.config_snapshot)?;
    let root = wf.resolved_path()?;
    assert_under_home(&root)?;

    let steps = wf.normalized_steps();
    let mut step_ids = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        let sid = db.insert_step(deployment_id, i as i32, &s.name)?;
        step_ids.push(sid);
    }

    log_line(
        db,
        deployment_id,
        None,
        "system",
        &format!(">>> 开始部署 {} (#{})\n", wf.name, deployment_id),
    )
    .await;

    let mut env: HashMap<String, String> = std::env::vars().collect();
    for (k, v) in &wf.env {
        env.insert(k.clone(), v.clone());
    }
    // 注入数据库中的 project secrets（覆盖同名 env）
    match db.load_secrets(job.project_id) {
        Ok(secrets) => {
            for (k, enc) in secrets {
                match crate::crypto::decrypt_secret(secret_key, &enc) {
                    Ok(v) => {
                        env.insert(k, v);
                    }
                    Err(e) => {
                        log_line(
                            db,
                            deployment_id,
                            None,
                            "stderr",
                            &format!("解密 secret {k} 失败: {e}\n"),
                        )
                        .await;
                        db.finish_deployment(deployment_id, "failed", 1)?;
                        return Ok(());
                    }
                }
            }
        }
        Err(e) => tracing::warn!("加载 secrets 失败: {e:#}"),
    }

    let mut final_code = 0i32;
    let mut cancelled = false;
    let mut after_sha: Option<String> = None;

    for (idx, step) in steps.iter().enumerate() {
        if db.is_cancel_requested(deployment_id)? {
            cancelled = true;
            break;
        }
        let step_id = step_ids[idx];
        db.mark_step_running(step_id)?;
        let started = Instant::now();

        let result = run_step(db, deployment_id, step_id, &wf, step, &root, &env).await;
        let elapsed = started.elapsed().as_millis() as i64;

        match result {
            Ok(StepResult::Ok { code, sha }) => {
                if let Some(s) = sha {
                    after_sha = Some(s);
                }
                let status = if code == 0 { "success" } else { "failed" };
                db.mark_step_finished(step_id, status, code, elapsed, "")?;
                if code != 0 {
                    final_code = code;
                    if !step.continue_on_error {
                        break;
                    }
                }
            }
            Ok(StepResult::Cancelled) => {
                db.mark_step_finished(step_id, "cancelled", 130, elapsed, "cancelled")?;
                cancelled = true;
                final_code = 130;
                break;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                log_line(
                    db,
                    deployment_id,
                    Some(step_id),
                    "stderr",
                    &format!("{msg}\n"),
                )
                .await;
                db.mark_step_finished(step_id, "failed", 1, elapsed, &msg)?;
                final_code = 1;
                if !step.continue_on_error {
                    break;
                }
            }
        }
    }

    if let Some(ref sha) = after_sha {
        let _ = db.set_git_sha(deployment_id, None, Some(sha));
    }

    let status = if cancelled {
        "cancelled"
    } else if final_code == 0 {
        "success"
    } else {
        "failed"
    };
    db.finish_deployment(deployment_id, status, final_code)?;
    log_line(
        db,
        deployment_id,
        None,
        "system",
        &format!("<<< 结束 status={status} exit_code={final_code}\n"),
    )
    .await;
    Ok(())
}

enum StepResult {
    Ok { code: i32, sha: Option<String> },
    Cancelled,
}

async fn run_step(
    db: &Db,
    deployment_id: i64,
    step_id: i64,
    wf: &ProjectWorkflow,
    step: &crate::workflow::NormalizedStep,
    root: &Path,
    env: &HashMap<String, String>,
) -> Result<StepResult> {
    match &step.kind {
        StepKind::Sync => {
            let git = wf.git.as_ref().context("sync 需要 git 配置")?;
            log_line(
                db,
                deployment_id,
                Some(step_id),
                "system",
                &format!("[sync] path={}\n", root.display()),
            )
            .await;
            let sha = git_sync(db, deployment_id, step_id, root, git).await?;
            Ok(StepResult::Ok {
                code: 0,
                sha: Some(sha),
            })
        }
        StepKind::HealthCheck { url } => {
            log_line(
                db,
                deployment_id,
                Some(step_id),
                "system",
                &format!("[health_check] {url}\n"),
            )
            .await;
            let timeout = Duration::from_secs(step.timeout.max(1));
            let code = health_check(url, timeout).await?;
            log_line(
                db,
                deployment_id,
                Some(step_id),
                "system",
                &format!("HTTP status={code}\n"),
            )
            .await;
            let exit = if (200..300).contains(&code) { 0 } else { code };
            Ok(StepResult::Ok {
                code: exit,
                sha: None,
            })
        }
        StepKind::Run { command } => {
            let cwd = match &step.dir {
                Some(d) => root.join(d),
                None => root.to_path_buf(),
            };
            if !cwd.is_dir() {
                bail!("工作目录不存在: {}", cwd.display());
            }
            let shell = step.shell.as_deref().unwrap_or(wf.shell.as_str());
            log_line(
                db,
                deployment_id,
                Some(step_id),
                "system",
                &format!("$ ({}) {}\n", cwd.display(), command),
            )
            .await;

            let code = run_shell(
                db,
                deployment_id,
                step_id,
                shell,
                command,
                &cwd,
                env,
                Duration::from_secs(step.timeout.max(1)),
            )
            .await?;
            if code == 130 {
                return Ok(StepResult::Cancelled);
            }
            Ok(StepResult::Ok { code, sha: None })
        }
    }
}

async fn git_sync(
    db: &Db,
    deployment_id: i64,
    step_id: i64,
    root: &Path,
    git: &crate::workflow::GitSpec,
) -> Result<String> {
    if root.exists() {
        if !(root.join(".git")).is_dir() {
            bail!("{} 已存在但不是 git 仓库", root.display());
        }
        // pull
        let before = git_sha(root).await.ok();
        if let Some(ref b) = before {
            let _ = db.set_git_sha(deployment_id, Some(b), None);
            log_line(
                db,
                deployment_id,
                Some(step_id),
                "system",
                &format!("before_sha={b}\n"),
            )
            .await;
        }
        run_git(db, deployment_id, step_id, root, &["checkout", &git.branch]).await?;
        run_git(db, deployment_id, step_id, root, &["pull", "--ff-only"]).await?;
    } else {
        if let Some(parent) = root.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let mut args = vec!["clone".to_string(), "--branch".into(), git.branch.clone()];
        if let Some(depth) = git.depth {
            args.push("--depth".into());
            args.push(depth.to_string());
        }
        args.push(git.url.clone());
        args.push(root.to_string_lossy().to_string());
        // clone 在父目录执行
        let parent = root.parent().unwrap_or(Path::new("/"));
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_git(db, deployment_id, step_id, parent, &arg_refs).await?;
    }
    let sha = git_sha(root).await?;
    log_line(
        db,
        deployment_id,
        Some(step_id),
        "system",
        &format!("after_sha={sha}\n"),
    )
    .await;
    Ok(sha)
}

async fn run_git(
    db: &Db,
    deployment_id: i64,
    step_id: i64,
    cwd: &Path,
    args: &[&str],
) -> Result<()> {
    log_line(
        db,
        deployment_id,
        Some(step_id),
        "system",
        &format!("$ git {}\n", args.join(" ")),
    )
    .await;
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("启动 git 失败")?;
    stream_output(db, deployment_id, step_id, &mut child).await?;
    let status = child.wait().await?;
    if !status.success() {
        bail!("git 失败: exit {:?}", status.code());
    }
    Ok(())
}

async fn git_sha(root: &Path) -> Result<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .await?;
    if !out.status.success() {
        bail!("rev-parse 失败");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn run_shell(
    db: &Db,
    deployment_id: i64,
    step_id: i64,
    shell: &str,
    command: &str,
    cwd: &Path,
    env: &HashMap<String, String>,
    timeout: Duration,
) -> Result<i32> {
    let shell_path = which::which(shell).with_context(|| format!("找不到 shell: {shell}"))?;
    // login interactive 以复用用户环境（asdf 等）
    let flag = if shell.ends_with("zsh") {
        "-lic"
    } else {
        "-lic"
    };

    let mut cmd = Command::new(shell_path);
    cmd.args([flag, command])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    // 新会话便于整组杀进程
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            // setsid
            if nix::unistd::setsid().is_err() {
                // ignore
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("启动命令失败")?;
    let pid = child.id();

    let cancel_check = async {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if db.is_cancel_requested(deployment_id).unwrap_or(false) {
                return true;
            }
        }
    };

    let run = async {
        stream_output(db, deployment_id, step_id, &mut child).await?;
        let status = child.wait().await?;
        Ok::<i32, anyhow::Error>(status.code().unwrap_or(1))
    };

    tokio::select! {
        res = run => res,
        _ = tokio::time::sleep(timeout) => {
            kill_child(pid);
            let _ = child.kill().await;
            log_line(db, deployment_id, Some(step_id), "stderr", "超时，已终止进程\n").await;
            Ok(124)
        }
        _ = cancel_check => {
            kill_child(pid);
            let _ = child.kill().await;
            log_line(db, deployment_id, Some(step_id), "stderr", "已取消\n").await;
            Ok(130)
        }
    }
}

fn kill_child(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        use nix::sys::signal::{killpg, Signal};
        use nix::unistd::Pid;
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGTERM);
        // 稍后 SIGKILL 由 kill_on_drop / 再次 kill 处理
    }
    let _ = pid;
}

async fn stream_output(
    db: &Db,
    deployment_id: i64,
    step_id: i64,
    child: &mut tokio::process::Child,
) -> Result<()> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let out_task = async {
        if let Some(out) = stdout {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_line(
                    db,
                    deployment_id,
                    Some(step_id),
                    "stdout",
                    &format!("{line}\n"),
                )
                .await;
            }
        }
    };
    let err_task = async {
        if let Some(err) = stderr {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_line(
                    db,
                    deployment_id,
                    Some(step_id),
                    "stderr",
                    &format!("{line}\n"),
                )
                .await;
            }
        }
    };
    tokio::join!(out_task, err_task);
    Ok(())
}

async fn health_check(url: &str, timeout: Duration) -> Result<i32> {
    // 使用系统 curl，避免再拉 hyper client 复杂度；也可用 reqwest
    let out = Command::new("curl")
        .args(["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time"])
        .arg(timeout.as_secs().to_string())
        .arg(url)
        .output()
        .await
        .context("执行 curl 失败，请安装 curl")?;
    let code_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let code: i32 = code_str.parse().unwrap_or(1);
    if !out.status.success() && code == 1 {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("health_check 失败: {err}");
    }
    Ok(code)
}

async fn log_line(db: &Db, deployment_id: i64, step_id: Option<i64>, stream: &str, message: &str) {
    if let Err(e) = db.append_log(deployment_id, step_id, stream, message) {
        tracing::warn!("写日志失败: {e:#}");
    }
}
