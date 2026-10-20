# 本地直接运行

在仓库根目录使用 Python 启动，Flask 直接提供已经构建好的 Vue 页面，无需 Docker 或单独启动 Vite。

```powershell
python -m pip install -r requirements-python.txt
$env:PYFAKA_HOST = '127.0.0.1'
$env:PYFAKA_PORT = '8099'
$env:PYFAKA_DEBUG = '0'
$env:PYFAKA_COOKIE_SECURE = '0'
python -B -u run.py
```

- 前台：http://127.0.0.1:8099/query
- 后台：http://127.0.0.1:8099/admin/login
- 停止：在运行服务的终端按 `Ctrl+C`。再次启动前确认端口未被原进程占用。

本次使用 Python 3.12.10 和 Node.js 22.20.0，项目依赖已经安装。Node.js 用于重新授权过程中的运行时逻辑；前端使用 `pyfaka_app/static/app/` 的当前构建。

2026-10-20 首次本地启动时，`data/` 中没有业务数据库，已初始化空 SQLite 库及管理员 `admin`。没有设置 `PYFAKA_ADMIN_PASSWORD` 时，初始密码为 `change-me`，首次登录必须修改。后续重启保留现有账号密码，不会重新初始化。

数据库保存在 `data/fakaipingtai_py.sqlite3`，应用密钥保存在 `data/secret_key.txt`。保留二者及任务历史；更换密钥会影响后台查看已加密保存的提取密码。应用启动自动检查并补齐缺失字段，包含密码保护、累计错误锁卡和管理员锁定；卡密已取消 24 小时时限，历史期限字段保留但不再限制访问。更新后端后重启应用，并同步新的前端构建产物。

本次服务只监听 `127.0.0.1:8099`，调试关闭，仅本机访问。进程由当前运行会话保持，不是开机自启服务；停止或重启电脑后可按上方命令启动。启动前任务历史备份和 HTTP 检查结果保存在 `artifacts/local-start-20261020-130351/`。

2026-10-20 本地服务已刷新至支持至少 6 位提取密码、丢失密码联系提示、管理员修改绑定密码及手动锁卡的版本。启动自动补齐密码版本与手动锁定字段，保留现有卡密、文件、首次提取时间和账号密码；旧游客会话需重新验证。升级前 SQLite 在线备份及 HTTP/数据校验记录保存在 `artifacts/admin-card-lock-20261020/local-restart/`。
