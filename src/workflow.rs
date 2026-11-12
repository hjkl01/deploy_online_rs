//! YAML 工作流定义与校验（类似 GitHub Actions，本地执行）

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// 项目工作流（用户编写的 YAML）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectWorkflow {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// 本地工作目录，支持 ~
    pub path: String,
    #[serde(default)]
    pub git: Option<GitSpec>,
    #[serde(default = "default_shell")]
    pub shell: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub steps: Vec<Step>,
}

fn default_shell() -> String {
    "bash".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSpec {
    pub url: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub depth: Option<u32>,
}

fn default_branch() -> String {
    "main".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Step {
    /// 内置动作
    Action(ActionStep),
    /// 任意 shell 命令
    Run(RunStep),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStep {
    pub name: String,
    pub action: String,
    /// health_check 使用
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub continue_on_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStep {
    pub name: String,
    pub run: String,
    /// 相对 path 的子目录
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default)]
    pub shell: Option<String>,
}

fn default_timeout() -> u64 {
    3600
}

impl ProjectWorkflow {
    pub fn parse(yaml: &str) -> Result<Self> {
        let wf: Self = serde_yaml::from_str(yaml).context("YAML 解析失败")?;
        wf.validate()?;
        Ok(wf)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 200 {
            bail!("name 无效");
        }
        if self.path.trim().is_empty() {
            bail!("path 不能为空");
        }
        if self.shell != "bash" && self.shell != "zsh" {
            bail!("shell 仅支持 bash 或 zsh");
        }
        if self.steps.is_empty() {
            bail!("至少需要一个 step");
        }
        for (i, step) in self.steps.iter().enumerate() {
            match step {
                Step::Action(a) => {
                    if a.name.trim().is_empty() {
                        bail!("steps[{i}].name 不能为空");
                    }
                    match a.action.as_str() {
                        "sync" => {
                            if self.git.is_none() {
                                bail!("action: sync 需要配置顶层 git.url");
                            }
                        }
                        "health_check" => {
                            let url = a.url.as_deref().unwrap_or("");
                            if !(url.starts_with("http://") || url.starts_with("https://")) {
                                bail!("steps[{i}] health_check 需要有效 url");
                            }
                        }
                        other => bail!("未知 action: {other}（支持 sync, health_check）"),
                    }
                }
                Step::Run(r) => {
                    if r.name.trim().is_empty() {
                        bail!("steps[{i}].name 不能为空");
                    }
                    if r.run.trim().is_empty() {
                        bail!("steps[{i}].run 不能为空");
                    }
                    if r.run.len() > 50_000 {
                        bail!("steps[{i}].run 过长");
                    }
                }
            }
        }
        Ok(())
    }

    /// 展开 ~ 后的绝对路径
    pub fn resolved_path(&self) -> Result<PathBuf> {
        expand_path(&self.path)
    }
}

pub fn expand_path(p: &str) -> Result<PathBuf> {
    let p = p.trim();
    if p == "~" {
        return dirs::home_dir().context("无法解析家目录");
    }
    if let Some(rest) = p.strip_prefix("~/") {
        let home = dirs::home_dir().context("无法解析家目录")?;
        return Ok(home.join(rest));
    }
    if p.starts_with('~') {
        bail!("仅支持 ~ 或 ~/... 形式的家目录路径");
    }
    let path = PathBuf::from(p);
    if path.is_absolute() {
        Ok(path)
    } else {
        // 相对路径：相对当前用户家目录，避免工作目录不确定
        let home = dirs::home_dir().context("无法解析家目录")?;
        Ok(home.join(path))
    }
}

/// 安全：工作目录必须落在用户家目录下（与旧版策略一致）
pub fn assert_under_home(path: &Path) -> Result<()> {
    let home = dirs::home_dir().context("无法解析家目录")?.canonicalize().unwrap_or_else(|_| dirs::home_dir().unwrap());
    let target = if path.exists() {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    } else {
        // 父目录已存在时尽量 canonicalize
        path.to_path_buf()
    };
    if target == home {
        return Ok(());
    }
    if !target.starts_with(&home) {
        // 对尚未创建的路径，检查逻辑前缀
        let home_s = home.to_string_lossy();
        let target_s = target.to_string_lossy();
        if !target_s.starts_with(home_s.as_ref()) && !target_s.starts_with(&format!("{home_s}/")) {
            bail!("path 必须位于用户家目录下: {} (home={})", target.display(), home.display());
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct NormalizedStep {
    pub name: String,
    pub kind: StepKind,
    pub dir: Option<String>,
    pub timeout: u64,
    pub continue_on_error: bool,
    pub shell: Option<String>,
}

#[derive(Debug, Clone)]
pub enum StepKind {
    Sync,
    HealthCheck { url: String },
    Run { command: String },
}

impl ProjectWorkflow {
    pub fn normalized_steps(&self) -> Vec<NormalizedStep> {
        self.steps
            .iter()
            .map(|s| match s {
                Step::Action(a) => NormalizedStep {
                    name: a.name.clone(),
                    kind: match a.action.as_str() {
                        "sync" => StepKind::Sync,
                        "health_check" => StepKind::HealthCheck {
                            url: a.url.clone().unwrap_or_default(),
                        },
                        _ => StepKind::Run {
                            command: format!("echo unsupported action"),
                        },
                    },
                    dir: a.dir.clone(),
                    timeout: a.timeout,
                    continue_on_error: a.continue_on_error,
                    shell: None,
                },
                Step::Run(r) => NormalizedStep {
                    name: r.name.clone(),
                    kind: StepKind::Run {
                        command: r.run.clone(),
                    },
                    dir: r.dir.clone(),
                    timeout: r.timeout,
                    continue_on_error: r.continue_on_error,
                    shell: r.shell.clone(),
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blog_example() {
        let yaml = include_str!("../examples/blog.yaml");
        let wf = ProjectWorkflow::parse(yaml).expect("parse");
        assert_eq!(wf.name, "blog");
        assert!(wf.git.is_some());
        assert!(!wf.normalized_steps().is_empty());
    }
}
