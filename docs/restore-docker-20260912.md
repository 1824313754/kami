# 恢复 Docker 部署版本

已将应用界面及静态资源恢复为 `pyfaka-docker-20260912.zip` 打包时的版本。恢复后的应用文件与部署包逐字节一致，前端源码采用对应的打包前快照。

页面恢复原有浅色卡密服务台，不包含后加的商业化宣传区、轨道动效或管理后台导航。保留部署包已有的 2FA 三行展示、导入与下载、sub2api 上传以及重新授权默认并发 10。

业务数据保持原状。历史进度日志保留并追加本次恢复记录。

验证记录见 `artifacts/restore-docker-20260912/VERIFICATION.txt`。如需撤销本次恢复，在仓库执行：

```powershell
& 'E:/Git/bin/bash.exe' artifacts/restore-docker-20260912/ROLLBACK.sh
```

该脚本恢复操作前的深色界面；检测到后续文件变更时停止。恢复后刷新浏览器。
