# VPSHub 运维与验收（个人 MVP）

面向自托管单管理员场景。刻意不做：Agent、WebAuthn、S3、asciicast、nftables 解封、面板自更新、CRM、SOCKS5 userinfo。

## 首次上线

1. 安装：`sudo bash scripts/install.sh`（或本地 `go run ./cmd/vpshub`）
2. 创建管理员（安装器已创建则跳过）→ 首次登录强制改密 → 绑定 TOTP
3. **初始化保险库**，把恢复密钥离线保存
4. 设置独立「查看密码」（Settings → View password），用于揭示凭证
5. 添加 VPS → 解锁保险库 → 写入 SSH 凭证 → Test SSH → 确认 host key
6. 跑一次 Scan；需要远程终端时在 `config.yaml` 打开 `webssh_enabled` / `sftp_enabled`

## 日常

| 动作 | 入口 |
|------|------|
| 解锁保险库 | 顶栏 / `/vault`（自动锁定见 `vault_lock_ttl`） |
| 改登录密码 | Settings → 登录密码，或首次 `/password` |
| CSV 导入 | VPS 列表 Import（成功会提示导入台数） |
| 备份面板 | Backups → 创建；恢复用 `vpshub restore-db -yes` |
| 健康检查 | `GET /healthz` → `{ok, vault, version, db_ok}` |
| 登录锁定 | Settings → 登录锁定；可 Clear / Clear all |
| 单机体检 | VPS 详情 → `#checkup`（Scan 后按区域看建议） |
| 舰队体检脚本 | 矩阵 / VPS 多选 → 选已发布脚本 → 跑任务 |

告警通道：`config.yaml` 或 `VPSHUB_ALERT_*`（webhook / telegram / smtp）。Settings 可发测试。

### AI 建议（可选，只建议不执行）

在 `config.yaml`（或环境变量）配置：

| 项 | 说明 |
|----|------|
| `ai_enabled` / `VPSHUB_AI_ENABLED` | 默认 `false` |
| `ai_base_url` / `VPSHUB_AI_BASE_URL` | OpenAI 兼容 API，默认 `https://api.openai.com/v1` |
| `ai_api_key` / `VPSHUB_AI_API_KEY` | 密钥，仅配置侧，不经 Settings API 回传 |
| `ai_model` / `VPSHUB_AI_MODEL` | 默认 `gpt-4o-mini` |

启用后：体检面板「AI 建议」调用 `POST /api/ai/advise`，基于最近 scan + findings 返回中文建议。**不会自动 SSH / 建任务**；执行仍走 vault + 任务确认。

### 内置运维脚本（风险分级）

- **published + 可批量**（只读/演练）：`security-baseline`、`conn-summary`、`process-top`、`disk-inodes`、`large-files-tmp`、`docker-prune-dry`、`apt-autoremove-dry`、`sysctl-network-tune-check`、`auth-log-tail` 等
- **draft 待审**（变更类）：`docker-prune`、`apt-autoremove`、`journal-vacuum` 等 — 审核并改为 published/approved 后才能实跑/批量

自定义脚本仍走脚本中心全流程（草稿 → 审核 → 任务）。

## 验收清单（基本完备）

- [ ] 登录 + TOTP；错误次数触发锁定并可清除
- [ ] 首次改密与 Settings 中轮换登录密码
- [ ] 保险库 init / unlock / lock / expire；锁定时顶栏横幅与 `/vault` 引导
- [ ] 查看密码配置后可揭示 SSH/面板密码
- [ ] VPS CRUD、CSV 导入反馈、软删/回收站
- [ ] 服务商 / 网站到期与 HTTP 探针
- [ ] Scan、任务演练/实跑、脚本审核流
- [ ] 维护窗口与 op_mode 拦截高风险操作
- [ ] 告警列表与规则；备份创建/下载
- [ ] `/healthz` 含 version；Settings 显示版本
- [ ] 中英切换；空列表有提示文案
- [ ] 仪表盘 Host Key / 扫描过期深链；VPS 列表最近扫描与 stale 筛选
- [ ] 矩阵「扫描当前列表」；任务脚本 allow_batch / allow_production 预检
- [ ] HostOps 安全更新演练/实跑；未绑定 TOTP 顶栏提示

## 运维增强验收（本版本「基本完整」）

- [ ] 单机：Scan → 体检条目覆盖 monitor / cleanup / upgrade / optimize / security
- [ ] 体检面板可一键创建演练 / 只读脚本任务 / 跳转脚本中心
- [ ] 变更清理脚本存在且默认 draft，需审核后才能批量实跑
- [ ] AI：未配置时 Settings / 体检明确提示；配置后基于 scan+findings 出中文建议且不自动执行
- [ ] 矩阵与 VPS 多选可快捷跑已发布体检脚本（`POST /api/tasks` type=script）
- [ ] 仪表盘 stale_scan 链到 VPS 列表；自定义脚本仍可走脚本中心全流程
- [ ] `go test ./...` 与前端 `npm run build` 通过

## 故障速查

- **vault_locked / 423**：解锁保险库后再试
- **op_mode_blocks**：把目标 VPS 调到允许变更的模式
- **outside_maintenance_window**：等窗口或任务勾选确认窗外执行
- **ai_disabled**：在 config 打开 `ai_enabled` 并设置 `ai_api_key`
- **db_ok=false**：检查 `data_dir` 与 SQLite 文件权限
