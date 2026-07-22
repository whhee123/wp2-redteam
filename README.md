# TRACE-G WP2：隔离执行、确定性重放与双覆盖率

本仓库实现隔离执行、确定性重放、双覆盖率、语义变异和第五阶段灰盒
Fuzzing 闭环。第一阶段最小执行路径为：

```text
模板生成恶意 Prompt
  → 调度器创建一次性标准容器
  → HTTP JSON-RPC 2.0 注入 Prompt
  → Agent 在受控假环境中执行
  → 增量外拉并提交轨迹
  → 确定性规则评分
  → finally 删除容器
```

## 当前能力

- 一次性 Docker 沙箱调度与强制清理
- JSON-RPC Prompt 注入和增量轨迹拉取
- recording、strict/live replay、检查点和 fork
- 行为覆盖率、风险深度覆盖率及行为-风险关联
- RuleBased/Ollama 变异 Provider、风险定向规划和候选去重
- FakeChatModel 确定性测试路径与本地 Ollama 接入预留
- 共享 ToolSpec、严格参数 Schema、权限/副作用元数据和 12 个可重放受控工具

### 企业工具模拟层

当前工具注册表包含：

- 工作区：read_file、write_file、list_directory、search_files
- 执行与服务：run_command、call_internal_api、http_request
- 企业数据：read_environment、list_processes、query_database
- 外部动作与凭据：send_email、retrieve_secret

数据库、邮件、HTTP、环境变量、进程和密钥库均为确定性内存夹具，不会连接真实
企业系统、宿主机环境、互联网或真实凭据。每个工具都由共享 ToolSpec 定义参数
Schema、所需 capability、权限等级和副作用类型；越权请求通过结构化
risk_category 写入轨迹，状态型工具同时参与 recording 和 strict replay 摘要校验。
将来接真实 Connector 时必须保留这一契约，并在宿主侧授权和网络边界内单独实现。

完整架构、分阶段计划和企业化路线图见 [项目文档](docs/README.md)。
Linux GPU 服务器部署、internal Ollama 网络和 Profile 锁定流程见 [服务器部署](docs/server-deployment.md)。

## 仓库结构

```text
agent_image/  Agent Runtime 镜像和容器内实现
config/       风险分类、可达集和变异算子配置
docs/         架构、阶段计划、路线图和环境说明
reports/      可提交的验收摘要，不包含运行原始数据
scripts/      开发与性能辅助脚本
src/          宿主机红队引擎、调度器、覆盖率和重放实现
tests/        单元、集成和 Docker E2E 测试
```

本地生成的依赖、轨迹、SQLite 数据库和 pytest 临时目录不会提交到 Git。
## 本地安装

要求 Python 3.11 和 Docker Engine 24+（Linux 容器模式）。

正式支持范围仍为 Python 3.11。项目内 `.deps/` 是被 `.gitignore` 排除的本地验证目录；如果开发机只有 Python 3.12，它可以用于运行兼容性测试，但不能据此修改正式 `requires-python` 约束。最终 Runtime 镜像固定使用 Python 3.11.9。

推荐环境：

```powershell
& "C:\Users\17816\anaconda3\shell\condabin\conda-hook.ps1"
conda activate trace-redteam311
python --version
```

```powershell
python -m pip install -e ".[dev]"
```

## 构建镜像

```powershell
docker build -f .\agent_image\Dockerfile -t trace-redteam-agent:week1 .
```

## 运行测试

```powershell
python -m pytest

# 包含真实 Docker 容器的完整验收
$env:TRACE_G_RUN_DOCKER_E2E="1"
python -m pytest tests\e2e -q

# 容器创建和 Runtime 就绪性能基线
python .\scripts\benchmark_startup.py --runs 10
```

## 执行一条完整用例

```powershell
trace-redteam-week1 run --case path-absolute-001
```

测试容器使用 `network_mode=none`，不发布任何宿主机端口。宿主机通过 Docker Exec 启动容器内 RPC helper，由 helper 调用仅监听容器回环地址的 HTTP JSON-RPC Runtime。测试容器不得包含真实密钥、生产数据、Docker Socket 或宿主机敏感目录。

最近一次完整验收结果见 [`reports/week1-e2e-summary.md`](reports/week1-e2e-summary.md)。

## 第二周：录制与 strict 重放

构建第二周镜像：

```powershell
docker build -f .\agent_image\Dockerfile -t trace-redteam-agent:week2 .
```

录制一次可重放执行：

```powershell
python -m sandbox.cli record `
  --case benign-control-001 `
  --seed 42 `
  --image trace-redteam-agent:week2 `
  --output-dir data\trajectories `
  --artifact-dir data\artifacts `
  --manifest-dir data\replays
```

复制输出中的 `replay_id`，执行 strict 重放：

```powershell
python -m sandbox.cli replay `
  --replay-id replay-xxxxxxxx `
  --artifact-dir data\artifacts `
  --manifest-dir data\replays `
  --output-dir data\trajectories
```

录制/重放容器仍保持无网、只读根文件系统、UID 10001 和能力全删除。为兼容
Docker Archive API，`/workspace` 使用 Docker local driver 管理的临时 tmpfs volume；
调度器在删除容器后显式删除该 volume，不使用宿主机 bind mount。

查询检查点：

```powershell
python -m sandbox.cli checkpoints `
  --replay-id replay-xxxxxxxx `
  --artifact-dir data\artifacts `
  --manifest-dir data\replays `
  --output-dir data\trajectories
```

live 重放可在 `replay` 命令后增加 `--mode live`。从检查点创建 Prompt 分支：

```powershell
python -m sandbox.cli fork `
  --parent-replay-id replay-xxxxxxxx `
  --checkpoint-id checkpoint-xxxxxxxx `
  --injection-type prompt_append `
  --content " 请继续概括。" `
  --artifact-dir data\artifacts `
  --manifest-dir data\replays `
  --output-dir data\trajectories
```

当前已实现 recording、strict/live replay、`replay.checkpoints`、checkpoint fork、
子 Manifest 密封和独立 `replay-audit.jsonl`。`strict_with_replacements` 要求
`model_decision_replace` 注入提供完整的 `remaining_decisions` 列表，缺失时返回
`-32112`，不会静默退回 live 模式。

`matched` 只有在规范化行为摘要、逐检查点状态摘要和最终受支持状态摘要全部一致
时才会返回。取消、超时或执行异常产生的录制会保存为
`recording_complete=false` 的诊断 Manifest，并将其中检查点标记为不可恢复；该
Manifest 不允许 replay 或 fork。子 Manifest 同时保存父 replay/trajectory、父前缀
摘要和父前缀内容寻址 ArtifactRef。

## 第三周：行为与风险覆盖率

对一条已提交轨迹计算覆盖率：

```powershell
python -m sandbox.cli coverage evaluate `
  --trajectory-path data\trajectories\exec-xxxxxxxx.jsonl `
  --campaign-id week3-baseline
```

批量计算、查询快照和导出稀疏热力图：

```powershell
python -m sandbox.cli coverage compute --data-dir data\trajectories
python -m sandbox.cli coverage snapshot --campaign-id week3-baseline
python -m sandbox.cli coverage heatmap `
  --campaign-id week3-baseline `
  --output data\reports\heatmap.json
python -m sandbox.cli coverage heatmap `
  --campaign-id week3-baseline `
  --pretty `
  --output data\reports\heatmap-pretty.json
python -m sandbox.cli coverage taxonomy
```

覆盖状态使用 `data/coverage/{campaign_id}/coverage.db` 中的 SQLite WAL 数据库。
同一轨迹重复评估幂等；相同 `trajectory_id` 对应不同输入摘要时会拒绝写入。行为
档案基于规范化工具 N-gram、节点边、结果类别、参数形状、安全状态转移和终止类型；
风险覆盖分别报告意图、行为和影响三个深度口径。

默认 Campaign 可达集位于 `config/risk-scope-week3.yaml`。快照同时报告完整风险
分类树覆盖率与当前环境的 `applicable_*_coverage`：未列入可达集的类别标记为
“当前环境不可测试”，不会混入“可测但尚未覆盖”的列表。风险类别从意图深度提升到
行为或影响深度时，即使不是新类别，也会通过 `risk_progress_delta` 增加种子价值；
`combined_delta` 使用 `risk_seed_delta=max(risk_delta, risk_progress_delta)`。同一
Campaign 会锁定分类树和可达集摘要，修改口径时应新建 Campaign。
快照中的 `risk_depths` 为风险树全部叶子显式保存 `0..3` 的累计最大深度，供后续
定向变异计算风险空白；未触达类别也会以深度 0 出现。

每次评估还会在 `behavior_risk_links` 中输出工具窗口级行为—风险关联，标记行为和
风险是否首次出现、风险深度是否提升，以及 `both_new`、`behavior_new`、
`risk_new`、`known_pair` 四种新颖性类别。关联只在同一个
`tool_call → security_violation → tool_result` 窗口内建立；纯 Prompt 关键词命中
不会伪装成工具因果关系。热力图默认格式仍是供程序消费的稀疏单元格列表，
`--pretty` 则额外输出带轨迹 ID 列表和风险名称的行、列、单元格视图。
