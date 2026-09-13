# Kami

账号文件管理与卡密查询服务，支持 2FA 重新授权和每个账号最多三次授权尝试。

`main` 分支提交后，GitHub Actions 自动验证代码、构建前后端并发布镜像：

```text
ghcr.io/1824313754/kami:main
```

首次部署复制 `.env.example` 为 `.env`，填写管理员密码和应用密钥，然后执行：

```bash
docker compose pull
docker compose up -d --no-build --remove-orphans
```

以后等待该提交的 Actions 发布成功，再重复以上两条命令即可更新。后台入口 `/admin/login`，查询入口 `/query`，默认端口 `8099`。当前镜像支持 Linux x86_64。

旧版本生产环境首次切换、数据目录保留、镜像认证及回滚说明见 [部署文档](docs/docker-deploy.md)。2FA 和重试行为见 [授权说明](docs/reauth-2fa-retry.md)。
