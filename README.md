# deploy_online (Rust)

单二进制 Linux 部署平台：GitHub Actions 风格 YAML 工作流，**本机直接执行**，无需 Docker。

前后端打进同一个可执行文件，拷到机器上即可运行。

## 已实现

- [x] YAML 工作流（`sync` / `run` / `health_check`）
- [x] 目录不存在则 `git clone`，存在则 `pull --ff-only`
- [x] 同进程 Worker + SQLite（WAL）
- [x] 登录会话、角色（admin 可写，viewer 只读）
- [x] Web UI：项目 YAML 编辑、一键部署、实时日志（WebSocket）
- [x] Project Secrets（加密存储，部署时注入环境变量）
- [x] 启动时按 `LOG_RETENTION_DAYS` 清理过期日志
- [x] CLI：`--import` / `--run` / `--bind` / `--data-dir`

## 要求

- **Rust 1.80+**（推荐 1.82；1.75 会因依赖 edition2024 无法解析）
- Linux，本机已安装 `git`、以及你 YAML 里用到的工具（`npm` / `uv` / `curl` 等）

## 构建（单二进制）

前端在 `static/`，编译时由 `rust-embed` 打进后端，**一个文件即可分发**：

```bash
make build
# 产物: dist/deploy_online
```

其它目标：`make run` / `make install` / `make clean` / `make help`。

## 快速开始

```bash
export SECRET_KEY="$(openssl rand -hex 32)"
export ADMIN_PASSWORD='换成强密码'

make build
./dist/deploy_online --bind 127.0.0.1:8000

# 另开终端导入示例
./dist/deploy_online --import examples/blog.yaml
./dist/deploy_online --run blog
```

浏览器打开 http://127.0.0.1:8000 登录即可。

## YAML 示例

```yaml
name: blog
path: ~/apps/blog
git:
  url: https://github.com/example/blog.git
  branch: main
shell: bash
env:
  NODE_ENV: production
steps:
  - name: Sync source
    action: sync
  - name: Frontend build
    run: npm ci && npm run build
    dir: frontend
    timeout: 900
  - name: Restart
    run: systemctl --user restart blog.service
  - name: Health
    action: health_check
    url: http://127.0.0.1:3000/health
```

## 模块

| 文件 | 职责 |
|------|------|
| `workflow.rs` | YAML 解析与校验 |
| `worker.rs` | git sync、shell、超时/取消、secret 注入 |
| `db.rs` | SQLite 模型与状态机 |
| `crypto.rs` | Secret 加解密 |
| `api.rs` | HTTP + WebSocket |
| `embed.rs` | 嵌入 `static/index.html` |
| `static/` | 内置控制台前端 |

## 环境变量

| 变量 | 说明 |
|------|------|
| `SECRET_KEY` | 必填，≥16 字符，用于会话与 secret 加密 |
| `ADMIN_PASSWORD` | 必填，首次启动创建管理员 |
| `ADMIN_USERNAME` | 默认 `admin` |
| `WORKER_CONCURRENCY` | 并行项目数，默认 4 |
| `LOG_RETENTION_DAYS` | 日志保留天数，默认 30 |
| `DEPLOY_ONLINE_BIND` | 监听地址 |
| `DEPLOY_ONLINE_DATA` | 数据目录（默认 XDG data） |
| `RUST_LOG` | 日志级别，默认 `info` |

完整示例见 [`.env.example`](.env.example)：`cp .env.example .env` 后填写 `SECRET_KEY` 与 `ADMIN_PASSWORD` 即可。

## 安全

- 部署以运行二进制的 Linux 用户身份执行任意 shell，勿对不可信用户开放。
- `path` 限制在用户家目录下。
- 默认只绑 `127.0.0.1`；公网请加反向代理与 HTTPS。

## License

MIT
