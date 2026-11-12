use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use crate::config::AppConfig;
use crate::crypto::{decrypt_secret, encrypt_secret};
use crate::db::{Db, UserRow};
use crate::embed::static_handler;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub cfg: AppConfig,
}

pub fn router(db: Arc<Db>, cfg: AppConfig) -> Router {
    let state = AppState { db, cfg };
    Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({"status":"ok"})) }))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/projects", get(list_projects).post(create_project))
        .route(
            "/api/projects/:id",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route("/api/projects/:id/deploy", post(deploy_project))
        .route(
            "/api/projects/:id/secrets",
            get(list_secrets).post(upsert_secret),
        )
        .route("/api/projects/:id/secrets/:key", delete(delete_secret))
        .route("/api/deployments", get(list_deployments))
        .route("/api/deployments/:id", get(get_deployment))
        .route("/api/deployments/:id/logs", get(get_logs))
        .route("/api/deployments/:id/cancel", post(cancel_deployment))
        .route("/api/deployments/:id/ws", get(ws_deployment))
        .fallback(static_handler)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .map(str::trim)
                .find_map(|p| p.strip_prefix("session=").map(|x| x.to_string()))
        })
}

fn require_user(state: &AppState, headers: &HeaderMap) -> Result<UserRow, ApiError> {
    let sid = session_id(headers).ok_or(ApiError::Unauthorized)?;
    state
        .db
        .user_from_session(&sid)?
        .ok_or(ApiError::Unauthorized)
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Response, ApiError> {
    let user = state
        .db
        .verify_user(&body.username, &body.password)?
        .ok_or(ApiError::BadRequest("用户名或密码错误".into()))?;
    let sid = state.db.create_session(user.id, 7)?;
    let cookie = format!("session={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800");
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true, "user": user})),
    )
        .into_response())
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(sid) = session_id(&headers) {
        let _ = state.db.delete_session(&sid);
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<UserRow>, ApiError> {
    Ok(Json(require_user(&state, &headers)?))
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_user(&state, &headers)?;
    let rows = state.db.list_projects()?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "enabled": p.enabled,
                "updated_at": p.updated_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!(items)))
}

#[derive(Deserialize)]
struct ProjectBody {
    name: String,
    #[serde(default)]
    description: String,
    yaml: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProjectBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    let id = state
        .db
        .upsert_project(&body.name, &body.description, &body.yaml, body.enabled)?;
    Ok(Json(serde_json::json!({"id": id, "name": body.name})))
}

async fn update_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ProjectBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    let _ = state.db.get_project(id)?.ok_or(ApiError::NotFound)?;
    let _ = crate::workflow::ProjectWorkflow::parse(&body.yaml)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();
    let c = state.db.conn()?;
    c.execute(
        "UPDATE projects SET name=?1, description=?2, yaml=?3, enabled=?4, updated_at=?5 WHERE id=?6",
        rusqlite::params![
            body.name,
            body.description,
            body.yaml,
            body.enabled as i64,
            now,
            id
        ],
    )?;
    Ok(Json(serde_json::json!({"id": id})))
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_user(&state, &headers)?;
    let p = state.db.get_project(id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(serde_json::json!({
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "yaml": p.yaml,
        "enabled": p.enabled,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })))
}

async fn delete_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    state.db.delete_project(id)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn deploy_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let dep_id = state.db.create_deployment(id, Some(user.id))?;
    Ok(Json(serde_json::json!({"id": dep_id})))
}

async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    let keys = state.db.list_secret_keys(id)?;
    Ok(Json(serde_json::json!({"keys": keys})))
}

#[derive(Deserialize)]
struct SecretBody {
    key: String,
    value: String,
}

async fn upsert_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<SecretBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    if body.key.is_empty() || body.key.contains('=') {
        return Err(ApiError::BadRequest("secret key 无效".into()));
    }
    let enc = encrypt_secret(&state.cfg.secret_key, &body.value)
        .map_err(|e| ApiError::Internal(e))?;
    state.db.upsert_secret(id, &body.key, &enc)?;
    Ok(Json(serde_json::json!({"ok": true, "key": body.key})))
}

async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, key)): Path<(i64, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    state.db.delete_secret(id, &key)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_page_size")]
    page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    20
}

async fn list_deployments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_user(&state, &headers)?;
    let (items, total) = state.db.list_deployments(q.page, q.page_size.min(100))?;
    Ok(Json(serde_json::json!({"items": items, "total": total})))
}

async fn get_deployment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_user(&state, &headers)?;
    let d = state.db.get_deployment(id)?.ok_or(ApiError::NotFound)?;
    let steps = state.db.list_deployment_steps(id)?;
    Ok(Json(serde_json::json!({
        "deployment": d,
        "steps": steps,
    })))
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default)]
    after: i64,
}

async fn get_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_user(&state, &headers)?;
    let logs = state.db.list_logs_after(id, q.after)?;
    let items: Vec<_> = logs
        .into_iter()
        .map(|(id, step_id, stream, message)| {
            serde_json::json!({"id": id, "step_id": step_id, "stream": stream, "message": message})
        })
        .collect();
    Ok(Json(serde_json::json!({"logs": items})))
}

async fn cancel_deployment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    if user.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    state.db.request_cancel(id)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn ws_deployment(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let _user = require_user(&state, &headers)?;
    let _ = state.db.get_deployment(id)?.ok_or(ApiError::NotFound)?;
    Ok(ws.on_upgrade(move |socket| ws_loop(socket, state, id)))
}

async fn ws_loop(socket: WebSocket, state: AppState, deployment_id: i64) {
    let (mut sender, mut receiver) = socket.split();
    let mut last_log: i64 = 0;
    let mut last_version: i64 = -1;

    // 初始快照
    if let Ok(logs) = state.db.list_logs_after(deployment_id, 0) {
        let payload: Vec<_> = logs
            .iter()
            .map(|(id, step_id, stream, message)| {
                last_log = *id;
                serde_json::json!({"id": id, "step_id": step_id, "stream": stream, "message": message})
            })
            .collect();
        let msg = serde_json::json!({"type": "snapshot", "logs": payload});
        let _ = sender.send(Message::Text(msg.to_string())).await;
    }

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(p))) => {
                        let _ = sender.send(Message::Pong(p)).await;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(800)) => {
                // 增量日志
                if let Ok(logs) = state.db.list_logs_after(deployment_id, last_log) {
                    for (id, step_id, stream, message) in logs {
                        last_log = id;
                        let msg = serde_json::json!({
                            "type": "log",
                            "id": id,
                            "step_id": step_id,
                            "stream": stream,
                            "message": message,
                        });
                        if sender.send(Message::Text(msg.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
                // 状态
                if let Ok(Some(dep)) = state.db.get_deployment(deployment_id) {
                    let ver = state.db.deployment_state_version(deployment_id).unwrap_or(0);
                    if ver != last_version {
                        last_version = ver;
                        let steps = state.db.list_deployment_steps(deployment_id).unwrap_or_default();
                        let msg = serde_json::json!({
                            "type": "status",
                            "status": dep.status,
                            "exit_code": dep.exit_code,
                            "steps": steps,
                        });
                        if sender.send(Message::Text(msg.to_string())).await.is_err() {
                            return;
                        }
                        if matches!(dep.status.as_str(), "success" | "failed" | "cancelled") {
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Internal(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match &self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "未登录".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "无权限".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "不存在".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal(e) => {
                tracing::error!("API error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        };
        (code, Json(serde_json::json!({"detail": msg}))).into_response()
    }
}

// silence unused import warning for decrypt in case only encrypt used in handlers
#[allow(dead_code)]
fn _keep_decrypt() {
    let _ = decrypt_secret;
}
