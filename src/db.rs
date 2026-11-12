use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

pub type DbPool = Pool<SqliteConnectionManager>;

pub struct Db {
    pool: DbPool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectRow {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub yaml: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeploymentRow {
    pub id: i64,
    pub project_id: i64,
    pub project_name: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub note: String,
    pub before_sha: Option<String>,
    pub after_sha: Option<String>,
    pub config_snapshot: String,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let manager = SqliteConnectionManager::file(path).with_init(|c| {
            c.execute_batch(
                "
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                PRAGMA foreign_keys=ON;
                PRAGMA busy_timeout=30000;
                ",
            )?;
            Ok(())
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .context("创建 SQLite 连接池失败")?;
        Ok(Self { pool })
    }

    pub fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool.get().context("获取数据库连接失败")
    }

    pub fn migrate(&self) -> Result<()> {
        let c = self.conn()?;
        c.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer'
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                yaml TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                key TEXT NOT NULL,
                value_enc TEXT NOT NULL,
                UNIQUE(project_id, key)
            );

            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                exit_code INTEGER,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                config_snapshot TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                before_sha TEXT,
                after_sha TEXT,
                state_version INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS ix_deployments_status ON deployments(status);
            CREATE INDEX IF NOT EXISTS ix_deployments_project ON deployments(project_id, created_at);

            CREATE TABLE IF NOT EXISTS deployment_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
                position INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                started_at TEXT,
                finished_at TEXT,
                exit_code INTEGER,
                duration_ms INTEGER,
                error TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS ix_steps_deployment ON deployment_steps(deployment_id, position);

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
                step_id INTEGER REFERENCES deployment_steps(id) ON DELETE SET NULL,
                stream TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_logs_deployment ON logs(deployment_id, id);

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn ensure_admin(&self, username: &str, password_hash: &str) -> Result<()> {
        let c = self.conn()?;
        let count: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if count == 0 {
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, 'admin')",
                params![username, password_hash],
            )?;
            tracing::info!("已创建初始管理员: {}", username);
        }
        Ok(())
    }

    pub fn verify_user(&self, username: &str, password: &str) -> Result<Option<UserRow>> {
        let c = self.conn()?;
        let row: Option<(i64, String, String, String)> = c
            .query_row(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?1",
                params![username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((id, uname, hash, role)) = row {
            if verify_password(password, &hash)? {
                return Ok(Some(UserRow {
                    id,
                    username: uname,
                    role,
                }));
            }
        }
        Ok(None)
    }

    pub fn create_session(&self, user_id: i64, days: i64) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let expires = (Utc::now() + chrono::Duration::days(days)).to_rfc3339();
        let c = self.conn()?;
        c.execute(
            "INSERT INTO sessions (id, user_id, expires_at) VALUES (?1, ?2, ?3)",
            params![id, user_id, expires],
        )?;
        Ok(id)
    }

    pub fn user_from_session(&self, session_id: &str) -> Result<Option<UserRow>> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        let row = c
            .query_row(
                "SELECT u.id, u.username, u.role FROM sessions s
                 JOIN users u ON u.id = s.user_id
                 WHERE s.id = ?1 AND s.expires_at > ?2",
                params![session_id, now],
                |r| {
                    Ok(UserRow {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        role: r.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn delete_session(&self, session_id: &str) -> Result<()> {
        let c = self.conn()?;
        c.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])?;
        Ok(())
    }

    pub fn import_project_yaml(&self, yaml: &str) -> Result<String> {
        let wf = crate::workflow::ProjectWorkflow::parse(yaml)?;
        let now = Utc::now().to_rfc3339();
        let c = self.conn()?;
        c.execute(
            "INSERT INTO projects (name, description, yaml, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)
             ON CONFLICT(name) DO UPDATE SET
               description=excluded.description,
               yaml=excluded.yaml,
               updated_at=excluded.updated_at",
            params![wf.name, wf.description, yaml, now],
        )?;
        Ok(wf.name)
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectRow>> {
        let c = self.conn()?;
        let mut stmt = c.prepare(
            "SELECT id, name, description, yaml, enabled, created_at, updated_at FROM projects ORDER BY name",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ProjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    yaml: r.get(3)?,
                    enabled: r.get::<_, i64>(4)? != 0,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_project(&self, id: i64) -> Result<Option<ProjectRow>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT id, name, description, yaml, enabled, created_at, updated_at FROM projects WHERE id = ?1",
            params![id],
            |r| {
                Ok(ProjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    yaml: r.get(3)?,
                    enabled: r.get::<_, i64>(4)? != 0,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_project_by_name(&self, name: &str) -> Result<Option<ProjectRow>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT id, name, description, yaml, enabled, created_at, updated_at FROM projects WHERE name = ?1",
            params![name],
            |r| {
                Ok(ProjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    yaml: r.get(3)?,
                    enabled: r.get::<_, i64>(4)? != 0,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn upsert_project(
        &self,
        name: &str,
        description: &str,
        yaml: &str,
        enabled: bool,
    ) -> Result<i64> {
        let _wf = crate::workflow::ProjectWorkflow::parse(yaml)?;
        let now = Utc::now().to_rfc3339();
        let c = self.conn()?;
        c.execute(
            "INSERT INTO projects (name, description, yaml, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(name) DO UPDATE SET
               description=excluded.description,
               yaml=excluded.yaml,
               enabled=excluded.enabled,
               updated_at=excluded.updated_at",
            params![name, description, yaml, enabled as i64, now],
        )?;
        let id: i64 = c.query_row(
            "SELECT id FROM projects WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn delete_project(&self, id: i64) -> Result<()> {
        let c = self.conn()?;
        c.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn create_deployment(&self, project_id: i64, user_id: Option<i64>) -> Result<i64> {
        let project = self.get_project(project_id)?.context("项目不存在")?;
        if !project.enabled {
            bail!("项目已禁用");
        }
        // 校验 YAML
        let _ = crate::workflow::ProjectWorkflow::parse(&project.yaml)?;
        let now = Utc::now().to_rfc3339();
        let c = self.conn()?;
        c.execute(
            "INSERT INTO deployments (project_id, user_id, status, created_at, config_snapshot)
             VALUES (?1, ?2, 'pending', ?3, ?4)",
            params![project_id, user_id, now, project.yaml],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn create_deployment_by_name(&self, name: &str, user_id: Option<i64>) -> Result<i64> {
        let p = self
            .get_project_by_name(name)?
            .with_context(|| format!("项目不存在: {name}"))?;
        self.create_deployment(p.id, user_id)
    }

    pub fn claim_pending(
        &self,
        exclude_project_ids: &[i64],
        capacity: usize,
    ) -> Result<Vec<(i64, i64)>> {
        if capacity == 0 {
            return Ok(vec![]);
        }
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;

        let mut running_projects: Vec<i64> = {
            let mut stmt =
                tx.prepare("SELECT DISTINCT project_id FROM deployments WHERE status = 'running'")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        running_projects.extend_from_slice(exclude_project_ids);

        let candidates: Vec<(i64, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT id, project_id FROM deployments WHERE status = 'pending' ORDER BY id LIMIT 100",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let mut claimed = Vec::new();
        let mut reserved = running_projects;
        let now = Utc::now().to_rfc3339();

        for (id, project_id) in candidates {
            if reserved.contains(&project_id) {
                continue;
            }
            let changed = tx.execute(
                "UPDATE deployments SET status = 'running', started_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![now, id],
            )?;
            if changed == 1 {
                claimed.push((id, project_id));
                reserved.push(project_id);
                if claimed.len() >= capacity {
                    break;
                }
            }
        }
        tx.commit()?;
        Ok(claimed)
    }

    pub fn recover_stale(&self) -> Result<()> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        c.execute(
            "UPDATE deployments SET status = 'failed', exit_code = 125, finished_at = ?1,
             note = note || char(10) || 'Worker 重启，任务中断'
             WHERE status = 'running'",
            params![now],
        )?;
        c.execute(
            "UPDATE deployment_steps SET status = 'failed', exit_code = 125, finished_at = ?1,
             error = 'Worker 重启，任务中断'
             WHERE status = 'running'",
            params![now],
        )?;
        Ok(())
    }

    pub fn get_deployment(&self, id: i64) -> Result<Option<DeploymentRow>> {
        let c = self.conn()?;
        c.query_row(
            "SELECT d.id, d.project_id, p.name, d.status, d.exit_code, d.created_at,
                    d.started_at, d.finished_at, d.note, d.before_sha, d.after_sha, d.config_snapshot
             FROM deployments d JOIN projects p ON p.id = d.project_id WHERE d.id = ?1",
            params![id],
            |r| {
                Ok(DeploymentRow {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    project_name: r.get(2)?,
                    status: r.get(3)?,
                    exit_code: r.get(4)?,
                    created_at: r.get(5)?,
                    started_at: r.get(6)?,
                    finished_at: r.get(7)?,
                    note: r.get(8)?,
                    before_sha: r.get(9)?,
                    after_sha: r.get(10)?,
                    config_snapshot: r.get(11)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn request_cancel(&self, id: i64) -> Result<()> {
        let c = self.conn()?;
        c.execute(
            "UPDATE deployments SET cancel_requested = 1 WHERE id = ?1 AND status IN ('pending','running')",
            params![id],
        )?;
        Ok(())
    }

    pub fn is_cancel_requested(&self, id: i64) -> Result<bool> {
        let c = self.conn()?;
        let v: i64 = c.query_row(
            "SELECT cancel_requested FROM deployments WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        Ok(v != 0)
    }

    pub fn insert_step(&self, deployment_id: i64, position: i32, name: &str) -> Result<i64> {
        let c = self.conn()?;
        c.execute(
            "INSERT INTO deployment_steps (deployment_id, position, name, status) VALUES (?1, ?2, ?3, 'pending')",
            params![deployment_id, position, name],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn mark_step_running(&self, step_id: i64) -> Result<()> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        c.execute(
            "UPDATE deployment_steps SET status = 'running', started_at = ?1 WHERE id = ?2",
            params![now, step_id],
        )?;
        c.execute(
            "UPDATE deployments SET state_version = state_version + 1 WHERE id =
               (SELECT deployment_id FROM deployment_steps WHERE id = ?1)",
            params![step_id],
        )?;
        Ok(())
    }

    pub fn mark_step_finished(
        &self,
        step_id: i64,
        status: &str,
        exit_code: i32,
        duration_ms: i64,
        error: &str,
    ) -> Result<()> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        c.execute(
            "UPDATE deployment_steps SET status = ?1, exit_code = ?2, duration_ms = ?3, error = ?4, finished_at = ?5 WHERE id = ?6",
            params![status, exit_code, duration_ms, error, now, step_id],
        )?;
        c.execute(
            "UPDATE deployments SET state_version = state_version + 1 WHERE id =
               (SELECT deployment_id FROM deployment_steps WHERE id = ?1)",
            params![step_id],
        )?;
        Ok(())
    }

    pub fn finish_deployment(&self, id: i64, status: &str, exit_code: i32) -> Result<()> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        c.execute(
            "UPDATE deployments SET status = ?1, exit_code = ?2, finished_at = ?3, state_version = state_version + 1 WHERE id = ?4",
            params![status, exit_code, now, id],
        )?;
        Ok(())
    }

    pub fn set_git_sha(&self, id: i64, before: Option<&str>, after: Option<&str>) -> Result<()> {
        let c = self.conn()?;
        c.execute(
            "UPDATE deployments SET before_sha = COALESCE(?1, before_sha), after_sha = COALESCE(?2, after_sha) WHERE id = ?3",
            params![before, after, id],
        )?;
        Ok(())
    }

    pub fn append_log(
        &self,
        deployment_id: i64,
        step_id: Option<i64>,
        stream: &str,
        message: &str,
    ) -> Result<i64> {
        let c = self.conn()?;
        let now = Utc::now().to_rfc3339();
        c.execute(
            "INSERT INTO logs (deployment_id, step_id, stream, message, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![deployment_id, step_id, stream, message, now],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn list_logs_after(
        &self,
        deployment_id: i64,
        after_id: i64,
    ) -> Result<Vec<(i64, Option<i64>, String, String)>> {
        let c = self.conn()?;
        let mut stmt = c.prepare(
            "SELECT id, step_id, stream, message FROM logs WHERE deployment_id = ?1 AND id > ?2 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![deployment_id, after_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_deployments(&self, page: i64, page_size: i64) -> Result<(Vec<DeploymentRow>, i64)> {
        let c = self.conn()?;
        let total: i64 = c.query_row("SELECT COUNT(*) FROM deployments", [], |r| r.get(0))?;
        let offset = (page.saturating_sub(1)) * page_size;
        let mut stmt = c.prepare(
            "SELECT d.id, d.project_id, p.name, d.status, d.exit_code, d.created_at,
                    d.started_at, d.finished_at, d.note, d.before_sha, d.after_sha, d.config_snapshot
             FROM deployments d JOIN projects p ON p.id = d.project_id
             ORDER BY d.id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![page_size, offset], |r| {
                Ok(DeploymentRow {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    project_name: r.get(2)?,
                    status: r.get(3)?,
                    exit_code: r.get(4)?,
                    created_at: r.get(5)?,
                    started_at: r.get(6)?,
                    finished_at: r.get(7)?,
                    note: r.get(8)?,
                    before_sha: r.get(9)?,
                    after_sha: r.get(10)?,
                    config_snapshot: r.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    pub fn list_secret_keys(&self, project_id: i64) -> Result<Vec<String>> {
        let c = self.conn()?;
        let mut stmt =
            c.prepare("SELECT key FROM project_secrets WHERE project_id = ?1 ORDER BY key")?;
        let rows = stmt
            .query_map(params![project_id], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn upsert_secret(&self, project_id: i64, key: &str, value_enc: &str) -> Result<()> {
        let c = self.conn()?;
        c.execute(
            "INSERT INTO project_secrets (project_id, key, value_enc) VALUES (?1, ?2, ?3)
             ON CONFLICT(project_id, key) DO UPDATE SET value_enc = excluded.value_enc",
            params![project_id, key, value_enc],
        )?;
        Ok(())
    }

    pub fn delete_secret(&self, project_id: i64, key: &str) -> Result<()> {
        let c = self.conn()?;
        c.execute(
            "DELETE FROM project_secrets WHERE project_id = ?1 AND key = ?2",
            params![project_id, key],
        )?;
        Ok(())
    }

    pub fn load_secrets(&self, project_id: i64) -> Result<Vec<(String, String)>> {
        let c = self.conn()?;
        let mut stmt =
            c.prepare("SELECT key, value_enc FROM project_secrets WHERE project_id = ?1")?;
        let rows = stmt
            .query_map(params![project_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn purge_old_logs(&self, retention_days: i64) -> Result<u64> {
        let c = self.conn()?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days)).to_rfc3339();
        let n = c.execute("DELETE FROM logs WHERE created_at < ?1", params![cutoff])?;
        Ok(n as u64)
    }

    pub fn list_deployment_steps(&self, deployment_id: i64) -> Result<Vec<serde_json::Value>> {
        let c = self.conn()?;
        let mut stmt = c.prepare(
            "SELECT id, position, name, status, started_at, finished_at, exit_code, duration_ms, error
             FROM deployment_steps WHERE deployment_id = ?1 ORDER BY position",
        )?;
        let rows = stmt
            .query_map(params![deployment_id], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "position": r.get::<_, i32>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "status": r.get::<_, String>(3)?,
                    "started_at": r.get::<_, Option<String>>(4)?,
                    "finished_at": r.get::<_, Option<String>>(5)?,
                    "exit_code": r.get::<_, Option<i32>>(6)?,
                    "duration_ms": r.get::<_, Option<i64>>(7)?,
                    "error": r.get::<_, String>(8)?,
                }))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn deployment_state_version(&self, id: i64) -> Result<i64> {
        let c = self.conn()?;
        let v: i64 = c.query_row(
            "SELECT state_version FROM deployments WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        Ok(v)
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| anyhow::anyhow!("hash error: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash).map_err(|e| anyhow::anyhow!("verify error: {e}"))
}
