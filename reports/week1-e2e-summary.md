# 第一周 Docker 端到端验收报告

- 验收日期：2026-07-15
- 标准镜像：`trace-redteam-agent:week1`
- 镜像摘要：`sha256:00b3e5d53972f347352cc02da9a61a184e7e8fcf65b81db5aa81ca7e3f3485a7`
- 容器 Python：3.11.9
- Docker Engine：29.6.1
- 非 Docker 单元/集成测试：34 项通过
- 真实 Docker 测试：15 项通过
- 验收后遗留沙箱容器：0
- 宿主机 Python：3.11.9（Conda `trace-redteam311`）

## 场景结果

| 编号 | 场景 | 结果 |
|---|---|---|
| 基线 | Docker 安全配置实测 | 通过 |
| E2E-01 | 允许文件读取 | 通过 |
| E2E-02 | `/etc/passwd` 越权读取 | 通过 |
| E2E-03 | 路径穿越 | 通过 |
| E2E-04 | 网络外传 | 通过 |
| E2E-05 | 无限循环超时 | 通过 |
| E2E-06 | 主动取消 | 通过 |
| E2E-07 | Runtime 崩溃 | 通过 |
| E2E-08 | 轨迹断档 | 通过 |
| E2E-09 | 无效能力令牌 | 通过 |
| E2E-10 | 重复提交与摘要冲突 | 通过 |
| E2E-11 | 连续十次隔离执行 | 通过 |
| E2E-12 | 评分器异常 | 通过 |
| E2E-13 | `write_file` 工具完整调用 | 通过 |
| E2E-14 | `call_internal_api` 工具完整调用 | 通过 |

## 已验证的隔离参数

- `HostConfig.NetworkMode == "none"`
- 非 root 用户 `10001:10001`
- 根文件系统只读
- `Privileged == false`
- `CapDrop == ["ALL"]`
- `no-new-privileges:true`
- 内存限制 512 MiB
- CPU 限制 1 核
- PIDs 限制 128
- `/tmp` 与 `/workspace` 为受限 tmpfs
- 不发布宿主机端口
- 执行完成或异常后无遗留容器

## 执行命令

```powershell
$env:TRACE_G_RUN_DOCKER_E2E="1"
python -m pytest tests\e2e -q
```

## 容器启动基线

缓存镜像条件下连续执行 10 次，统计口径如下：

| 指标 | P50 | P95 |
|---|---:|---:|
| `scheduler.create()` | 0.354 秒 | 0.411 秒 |
| 创建开始至 Runtime 健康就绪 | 2.607 秒 | 2.663 秒 |

执行命令：

```powershell
python .\scripts\benchmark_startup.py --runs 10
```

宿主机与正式 Runtime 镜像均已使用并实测 Python 3.11.9。
