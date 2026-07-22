# TRACE-G 服务器部署前置流程

本流程用于单机 NVIDIA GPU、Docker Engine 和本地 Ollama。正式 Campaign 中，Agent
只能通过 Docker internal bridge 访问 Ollama；11434 仅绑定宿主机回环地址，不得在
云安全组或主机防火墙中公开。

## 1. 环境

- 安装 Python 3.11、Docker Engine、Docker Compose plugin、NVIDIA 驱动和
  NVIDIA Container Toolkit。
- 云安全组仅开放管理所需的 SSH 来源地址。
- 为 `data/` 和 Ollama 模型卷预留持久磁盘。

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp deploy/.env.server.example deploy/.env.server
```

编辑 `deploy/.env.server`，设置精确的 `MODEL_NAME`，并将 `OLLAMA_IMAGE` 设置为
`ollama/ollama@sha256:<manifest-digest>` 形式的不可变 registry digest。首次仅使用
`OLLAMA_NUM_PARALLEL=1` 和单个 Sandbox Worker。

## 2. 拉取并锁定

```bash
set -a
source deploy/.env.server
set +a
bash scripts/pull_and_lock_model.sh
```

脚本会启动 Ollama、构建 Agent 镜像、临时为 Ollama 增加模型下载网络，下载完成后
立即撤销该网络，然后生成 `config/target-profiles.server.yaml`。该文件包含真实模型
digest、Agent 镜像 digest 和正在运行的 Ollama 镜像 digest，不得手工填写占位值。

## 3. 预检

```bash
export OLLAMA_IMAGE="$(docker inspect -f '{{.Config.Image}}' trace-g-ollama)"
bash scripts/server_preflight.sh
```

预检会验证 GPU 容器、Ollama 健康、internal network 标签、Agent 到 Ollama 的访问、
Agent 公网阻断、Profile 文件、静态检查和非 Docker 测试。

## 4. 分阶段验证

先运行一个用例，不要直接启动长 Campaign：

```bash
MODEL_DIGEST="$(python -c 'import yaml; print(yaml.safe_load(open("config/target-profiles.server.yaml"))["profiles"][0]["model_digest"])')"
MODEL_NAME="$(python -c 'import yaml; print(yaml.safe_load(open("config/target-profiles.server.yaml"))["profiles"][0]["model_name"])')"

python -m sandbox.cli run \
  --case benign-control-001 \
  --image trace-redteam-agent:server \
  --model-provider ollama \
  --model-name "$MODEL_NAME" \
  --model-digest "$MODEL_DIGEST" \
  --ollama-endpoint http://ollama:11434 \
  --model-network trace-g-model-internal
```

随后依次执行 Docker E2E、5 次恶意模板、25 次 smoke Campaign、1 小时 Soak，最后才
提高并发或运行 24 小时 Campaign。服务器阶段保持 `deterministic_rounds`，直到吞吐
调度和宿主资源预检完成正式验证。

Campaign 的 Agent endpoint 使用 `http://ollama:11434`；宿主机 Mutation Provider
使用 `http://127.0.0.1:11434`。两者不能互换。
