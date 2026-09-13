# Docker Deployment

本文档用于通过 GHCR 镜像将当前项目部署到 Linux x86_64 服务器。main 分支提交后由 GitHub Actions 自动构建、发布并执行镜像启动检查。

## 文件

- `docker-compose.yml`：仓库根目录的生产 Compose 配置，默认拉取 `ghcr.io/1824313754/kami:main`。
- `.env.example`：仓库根目录的环境变量模板。
- `Dockerfile`、`run.py`、`requirements-python.txt`、`pyfaka_app/`：镜像构建和应用文件。

## 快速部署

服务器需要先安装 Docker Engine 和 Docker Compose 插件。首次部署先取得仓库，进入目录并初始化环境文件：

```bash
git clone https://github.com/1824313754/kami.git
cd kami
cp .env.example .env
openssl rand -base64 48
openssl rand -hex 16
```

将两条随机命令的输出分别写入 `.env` 的 `PYFAKA_SECRET_KEY` 和 `PYFAKA_ADMIN_PASSWORD`，然后启动：

```bash
docker compose config --quiet
docker compose pull
docker compose up -d --no-build --remove-orphans
docker compose ps
```

管理员账号和密码只在数据目录首次初始化时生效。后续升级必须保留 `.env` 和数据目录。

默认访问地址：

- 后台：`http://服务器IP:8099/admin/login`
- 前台：`http://服务器IP:8099/query`

## 常用命令

```bash
docker compose pull
docker compose up -d --no-build --remove-orphans
docker compose ps
docker compose logs -f --tail=200
docker compose down
docker compose config
```

`down` 只停止容器，不删除数据目录中的数据。Compose 默认使用部署目录内的 `./data` 挂载到容器 `/app/data`，也可以通过 `PYFAKA_DATA_DIR` 覆盖。

Compose 已将容器 `nofile` 软硬限制设置为 `65535`，用于支持大批量上传和并发任务。

## 配置项

部署前编辑 `.env`：

- `PYFAKA_DATA_DIR`：宿主机数据目录，默认使用解压目录内的 `./data`。
- `PYFAKA_BIND_ADDRESS`：宿主机监听地址；仅由同机反向代理访问时可改为 `127.0.0.1`。
- `PYFAKA_HTTP_PORT`：宿主机暴露端口，默认值是 `8099`。
- 数据库固定使用内置 SQLite，发布 Compose 不读取宿主机的 `PYFAKA_DATABASE_URL`；数据库文件位于挂载数据目录的 `fakaipingtai_py.sqlite3`。
- `PYFAKA_ADMIN_USERNAME` / `PYFAKA_ADMIN_PASSWORD`：数据库首次初始化时使用的管理员账号和密码；生产部署应通过 `.env` 设置，不要写入 Compose 文件。
- `PYFAKA_COOKIE_SECURE`：通过 HTTPS 访问时设为 `1`；仅 HTTP 访问时保持 `0`。
- `PYFAKA_MAX_CONTENT_LENGTH`：上传请求最大字节数。
- `PYFAKA_MAX_FORM_MEMORY_SIZE`：表单内存阈值字节数。
- `PYFAKA_MAX_FORM_PARTS`：multipart 最大 part 数。
- `PYFAKA_REAUTH_PROXY`：游客二次登录验证的 OAuth 代理，留空时直连；2FA 验证码由服务器本地生成，不访问邮箱服务。
- 原 `PYFAKA_REAUTH_OTP_TIMEOUT` 邮件轮询配置已停用；2FA 使用标准 30 秒 TOTP 周期，服务器时钟须准确。

镜像已包含二次登录验证所需的 Node.js Sentinel 运行时，以及 `curl-cffi`、`requests`；TOTP 使用 Python 标准库。

## 数据和备份

业务数据保存在数据目录中，包括 SQLite 数据库、密钥文件、下载任务包和任务历史。账号 auth 内容按字段拆分保存在 SQLite 的 `file_record_payload_py` 表中，不再为新上传账号生成 `data/auth_files/*.json`。

默认数据目录是部署目录内的 `./data`，备份该目录即可。

应用仅在 SQLite 连接上启用 WAL 和 30 秒 `busy_timeout`，用于降低上传、下载、任务轮询等并发读写时出现 `database is locked` 的概率。

升级时等待 GitHub Actions 中对应提交的 Publish Docker image 成功，保留 `.env` 和 `PYFAKA_DATA_DIR`，在原部署目录执行：

```bash
docker compose pull
docker compose up -d --no-build --remove-orphans
```

## 旧生产环境首次切换

在原生产目录替换 `docker-compose.yml` 为本仓库版本。保留原 `.env`，将其中 `PYFAKA_IMAGE` 改为 `ghcr.io/1824313754/kami:main`；如果原来没有这个变量，可以不填，Compose 默认使用该镜像。尤其不要继续保留 `PYFAKA_IMAGE=pyfaka:latest`。

沿用现有 `PYFAKA_DATA_DIR`、`PYFAKA_CONTAINER_NAME`、`COMPOSE_PROJECT_NAME`、端口以及管理员配置。数据目录必须指向原数据库所在目录。如果以前没有 `.env`，先按 `.env.example` 补齐原配置；应用密钥沿用原环境值或原数据目录 `secret_key.txt` 的内容。不要用模板中的占位值替换生产密钥。旧容器名称若为 `pyfaka-8099`，就在 `.env` 中设置 `PYFAKA_CONTAINER_NAME=pyfaka-8099`。

完成一次切换后，日常程序更新只需 `docker compose pull` 和 `docker compose up -d --no-build --remove-orphans`，无需在服务器构建或执行 `git pull`。如果未来改动部署配置，需另同步 Compose 配置。

## 镜像权限与版本回滚

镜像使用与 pp-plus 相同的 GitHub Container Registry。若服务器已经登录 GHCR 且有这个镜像的读取权限，可直接拉取。新 GHCR 包可能默认是私有；若拉取提示 denied，在 GitHub 包设置中将 kami 镜像设为 Public，或者在服务器仅执行一次登录（使用拥有 `read:packages` 权限的令牌）：

```bash
read -rsp 'GitHub token: ' GHCR_TOKEN; echo
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u 1824313754 --password-stdin
unset GHCR_TOKEN
```

每次发布生成 `main`、`latest` 和 `sha-完整提交号` 标签。需要回滚时在 `.env` 中将 `PYFAKA_IMAGE` 改为 `ghcr.io/1824313754/kami:sha-目标完整提交号`，再执行两条更新命令。回到持续更新时改回 `:main`。现有数据目录保持原挂载；首次迁移前保存旧镜像 ID 和现有配置，便于回到迁移前版本。

## 反向代理

如果前面接 Nginx、Caddy 或其他 HTTPS 反向代理，建议：

- 只允许代理访问容器端口，避免应用端口直接暴露到公网。
- `.env` 中设置 `PYFAKA_COOKIE_SECURE=1`。
- 代理转发 `X-Forwarded-Proto: https`。

Nginx 与 Docker 位于同一台服务器时，上游端口必须与 Compose 的 `8099` 一致：

```nginx
location / {
    proxy_pass http://127.0.0.1:8099;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

当前应用会读取 `X-Forwarded-For` 作为客户端 IP，因此只有在可信反向代理后面使用该头才可靠。
