# PyFaka Docker 部署包 · 2026-09-12

本包包含当前应用源码和已编译前端，通过 Docker Compose 在服务器构建并启动。构建时需要联网下载 Python 基础镜像和依赖。

包含本次更新：2FA 库导入及邮箱匹配、游客 2FA TXT 下载、sub2api JSON 上传、重新授权默认并发 10，以及邮箱/密码/2FA 动态码三行展示。

## 启动

服务器安装 Docker Engine 和 Docker Compose 插件后，解压并进入目录：

```bash
mkdir -p pyfaka
unzip pyfaka-docker-20260912.zip -d pyfaka
cd pyfaka
cp .env.example .env
openssl rand -base64 48
openssl rand -hex 16
```

编辑 `.env`，将上述两条随机命令的输出分别填入 `PYFAKA_SECRET_KEY` 和 `PYFAKA_ADMIN_PASSWORD`。默认管理员用户名为 `admin`，也可以修改 `PYFAKA_ADMIN_USERNAME`。

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 pyfaka
```

- 前台：`http://服务器IP:8099/query`
- 后台：`http://服务器IP:8099/admin/login`
- 数据：当前目录 `./data`，使用内置 SQLite。
- OAuth 代理：按需填写 `.env` 的 `PYFAKA_REAUTH_PROXY`。
- 2FA 使用本地 TOTP，服务器时间应保持同步。

管理员初始账号密码只在数据库首次初始化时生效。部署包仅包含程序和配置模板；现有数据需要单独迁移。

## 升级和恢复

升级前停止旧容器，备份当前程序目录、`.env` 和 `data`。将新版程序解压至部署目录，保留原 `.env` 和 `data`，然后执行：

```bash
docker compose up -d --build --force-recreate
```

需要恢复旧版本时，先执行 `docker compose down`，恢复升级前备份的程序、`.env` 和 `data`，再执行 `docker compose up -d --build`。

## 验证情况

验证包含 Compose 配置解析、ZIP 完整性、解压后的应用初始化及页面和静态资源检查，以及 2FA、重新授权和 sub2api 导入回归。打包机器的 Docker 引擎未启动，容器镜像构建与容器运行尚未实测。

完整配置说明见 `docs/docker-deploy.md`。
