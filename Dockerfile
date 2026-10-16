# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
#
# BASE_IMAGE 可覆盖，用于 Docker Hub 不可达时走镜像源，例如：
#   docker build --build-arg BASE_IMAGE=mirror.example.com/python:3.12-slim-bookworm -t artex:local .
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# 预装渗透常备 Python 库。两个理由，第二个是修一个实测过的真实事故：
#
# 1) 消除每个任务重复联网装包的噪音。镜像是 python:slim，这些库一个都没有；
#    Agent 需要时会自己 `pip install`，实测一次任务里这类流量占了录制总量的
#    45%（pypi.org 24 条 + files.pythonhosted.org 46 条），既慢又污染流量库。
#
# 2) 把 Agent 引向"代理感知"的写法。出网代理是按环境变量注入 Bash 子进程的
#    （见 agent/worker.go 的 proxyEnv），底层库根本不读它：http.client、裸 socket、
#    Node 20 的 fetch 都会带着平台真实出口 IP 直连目标，绕过记录监听器与全局代理，
#    且两边都不留记录。实测事故：镜像里当时没有 requests，Agent 手搓 http.client
#    做盲注，353 次请求全部直连，真实 IP 落进了目标的服务端日志。
#
# 分组说明（都选纯 Python 或有 manylinux wheel，slim 上无需编译）：
#   HTTP/Web：requests[socks]（含 PySocks）、httpx[http2,socks]、beautifulsoup4+lxml（解析）
#   数据库/中间件：pymysql(MySQL) redis psycopg2-binary(PostgreSQL) pymongo(MongoDB)
#   协议/域：paramiko(SSH，sock= 可接 PySocks socket)、impacket(SMB/MSRPC/MSSQL)、ldap3、dnspython
#   其它：pycryptodome(加解密)、pyjwt(JWT)、websocket-client
# 注意：这些库自己不会读代理变量，裸 TCP 必须由脚本显式走 SOCKS5（见 worker prompt
# 里的 set_default_proxy 通用配方）；pysocks 就是为此显式保留的。
RUN pip install --no-cache-dir \
      requests[socks] pysocks httpx[http2,socks] beautifulsoup4 lxml \
      pymysql redis psycopg2-binary pymongo \
      paramiko impacket ldap3 dnspython \
      pycryptodome pyjwt websocket-client
# iptables 装在**最后一层**：它只影响这一层，前面的 Node/Playwright/pip 层保持缓存。
# 早前把它并进第 21 行的 apt 会让后面三层（含 Playwright 下载浏览器 ~150MB）全部失效重建。
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
# ---- S3：agent 出网收敛所需的部件 ----
# 1) 专属 uid：平台的命令以 root 跑，agent 的命令降权到它，内核才分得开（见 agent/worker.go）
# 2) bash 包装：SDK 执行的是裸名 "bash"，Go 按父进程 PATH 解析，环境变量改不了它指向哪个二进制，
#    所以在镜像里换掉 /usr/bin/bash —— 只有带 ARTEX_AGENT_UID 的调用才降权，平台自身不受影响。
# 3) 规则脚本：只放行回环（=listener），其余 REJECT，按 uid 生效。
RUN useradd -u 1001 -M -s /usr/sbin/nologin artex-agent \
 && mkdir -p /app/deploy \
 && mv /usr/bin/bash /usr/bin/bash.real \
 && ln -sf /usr/bin/bash.real /bin/bash.real || true
COPY deploy/agent-bash-wrapper.sh /app/deploy/agent-bash-wrapper.sh
COPY deploy/egress-lockdown.sh /app/deploy/egress-lockdown.sh
RUN install -m 0755 /app/deploy/agent-bash-wrapper.sh /usr/bin/bash \
 && ln -sf /usr/bin/bash /bin/bash \
 && chmod +x /app/deploy/egress-lockdown.sh \
 && /usr/bin/bash --version | head -1 \
 && /app/deploy/egress-lockdown.sh status || true
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
