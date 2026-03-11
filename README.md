# ssl-manager

一个用于在单台 VPS 上集中申请/续签 SSL 证书并下载使用的轻量面板。  
核心目标：**不要求在宝塔里逐个添加域名**，只要域名解析到本机、80 端口可访问，即可通过 HTTP-01 申请证书，并在面板里下载证书文件。

## 功能特性

- 在线申请免费证书（Let’s Encrypt，HTTP-01）
- 证书列表管理：查看到期时间、下载证书/私钥/打包下载
- 自动续签：后台定时扫描即将到期证书并自动续签
- 支持宝塔面板部署证书到站点（可选）：配置本机宝塔 API 后可一键部署并重载 Nginx
- 一键配置 Nginx 默认站点 ACME 转发（推荐）：让“任意解析到本机的域名”都能通过验证
- 操作日志：记录签发/续签/部署等事件

## 工作原理（关键点）

Let’s Encrypt 的 HTTP-01 校验会访问：

`http://<你的域名>/.well-known/acme-challenge/<token>`

如果你的 Nginx 没有匹配这个域名的 `server_name`，通常会落到默认站点并返回 404，导致签发失败。  
本项目通过两种方式解决：

1. **推荐：配置 Nginx 默认站点转发 ACME challenge 到本面板**
   - 不需要在宝塔里添加任何域名/子域名
   - 只要 DNS 解析到本机，80 可访问即可
2. **传统：让域名/子域名在宝塔站点里存在**
   - 由宝塔站点根目录直接提供 `/.well-known/` 文件

本项目默认使用 `DATA_DIR/acme-webroot` 作为 ACME Webroot，并在签发前做“可达性自检”（写入随机文件后立刻用 HTTP 访问验证），避免盲目等待 CA 失败。

## 为什么有时需要重载 Nginx？

只有在你“修改了 Nginx 配置文件”时，新的转发规则才会生效；Nginx 必须 reload 才会加载新配置。  
一旦 `/.well-known/acme-challenge/` 的转发规则配置完成并生效，后续续签/签发 **不需要每次都 reload**。

本项目会在检测到 HTTP-01 返回 404 时，尝试自动修复并触发重载：
- 优先通过宝塔面板 API 触发 Nginx reload（推荐做法）
- 若宝塔版本/接口不支持，则会提示你在宿主机手动执行一次 reload（通常只需要一次）

> 说明：容器内的 `nginx`/`systemctl` 命令通常不存在，即使你在宿主机已安装并运行 Nginx。  
> 因此“容器内自动执行 `nginx -s reload`”在默认 Docker 部署方式下不可行，本项目主要依赖宝塔 API 来触发宿主机 Nginx 重载。
>
> 当页面提示类似“宝塔未提供可用的重载接口（请手动重载 Nginx）”时，请你在**宝塔所在宿主机**手动重载一次（任选其一）：
>
> ```bash
> nginx -t && nginx -s reload
> ```
>
> ```bash
> systemctl reload nginx
> ```
>
> ```bash
> /www/server/nginx/sbin/nginx -t && /www/server/nginx/sbin/nginx -s reload
> ```
>
> 手动重载成功后，再回到面板点击“申请/续签”即可通过 HTTP-01 校验。

## 快速部署（Docker，推荐）

### 1) 拉取镜像

```bash
docker pull superneed/ssl-manager:latest
```

### 2) 运行容器（推荐 host 网络）

使用 host 网络的好处：
- 证书校验链路更简单（面板监听 8088，Nginx 默认站点转发到 127.0.0.1:8088）
- 可直接访问本机宝塔面板 `127.0.0.1:22460`（用于自动部署证书/重载）

```bash
docker rm -f ssl-manager 2>/dev/null || true

docker run -d \
  --name ssl-manager \
  --network host \
  -e PORT=8088 \
  -e TZ=Asia/Shanghai \
  -e AUTO_RENEW=1 \
  -e DATA_DIR=/data \
  -v /data/ssl-manager:/data \
  -v /www/server/panel/vhost/nginx:/www/server/panel/vhost/nginx:rw \
  -v /www/server/panel:/www/server/panel:ro \
  --restart unless-stopped \
  superneed/ssl-manager:latest
```

访问：`http://服务器IP:8088/`

如果你不使用 `--network host`，而是用 `-p` 映射端口（例如 `-p 8088:8080`），请额外设置：
- `PORT=8080`（容器内监听端口）
- `ACME_PROXY_PORT=8088`（写入 Nginx 配置时的宿主机端口）

### 3) 一键配置 Nginx 默认站点（强烈推荐）

进入面板：`本机宝塔设置` 页面，点击：

`一键配置 ACME 转发`

它会尝试写入（可通过环境变量覆盖）：
- 默认站点文件：`/www/server/panel/vhost/nginx/0.default.conf`
- 转发目标：`http://127.0.0.1:<PORT>`

并尝试通过宝塔 API 触发 Nginx 重载（若失败会提示你手动重载）。

> 注意：容器需要把 `/www/server/panel/vhost/nginx` 以 `rw` 方式挂载进去，否则会提示没有写入权限。
> 
> 若提示宝塔不支持重载接口，请在宿主机执行一次：`nginx -t && nginx -s reload`。

## 手动配置 Nginx 默认站点（不依赖按钮）

编辑：

`/www/server/panel/vhost/nginx/0.default.conf`

写入：

```nginx
server
{
    listen 80;
    server_name _;

    location ^~ /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    index index.html;
    root /www/server/nginx/html;
}
```

然后执行：

```bash
nginx -t && nginx -s reload
```

## 申请证书

1. 确保域名 A 记录解析到当前服务器 IP
2. 确保 80 端口对外可访问（防火墙/安全组开放）
3. 面板点击“申请免费证书”，输入域名（逗号分隔）并提交
4. 成功后进入“查看/下载”页，下载证书/私钥或 zip 包

## 自动续签

默认开启：`AUTO_RENEW=1`  
逻辑：
- 启动后延迟 120 秒开始
- 每 24 小时扫描一次
- 对剩余天数 ≤ 30 的证书执行 `acme.sh --renew`

## 手动“续签”的含义

面板里的“续签”按钮会强制重新签发（等同强制续签），用于把剩余天数重新拉回到接近 90 天。  
注意：Let’s Encrypt 有频率限制，请避免短时间内反复点击同一域名的续签。

## 环境变量

- `PORT`：面板监听端口（默认 8080）
- `DATA_DIR`：数据目录（默认 `/data`，包含数据库与 acme-webroot）
- `AUTO_RENEW`：是否启用自动续签线程（默认 `1`）
- `NGINX_DEFAULT_CONF`：Nginx 默认站点配置文件路径（默认 `/www/server/panel/vhost/nginx/0.default.conf`）
- `ACME_PROXY_PORT`：写入 Nginx 转发时使用的端口（默认等于 `PORT`）

## 常见问题

### 1) 申请失败：HTTP 404（无法访问挑战文件）

说明 Nginx 没有把 `/.well-known/acme-challenge/` 正确指向本面板的 ACME Webroot。  
解决方式：
- 使用“本机宝塔设置”页的“一键配置 ACME 转发”
- 或按 README 的“手动配置 Nginx 默认站点”添加 `location` 转发

### 2) 容器内提示无法写入默认站点文件

需要把目录挂载为可写：

`-v /www/server/panel/vhost/nginx:/www/server/panel/vhost/nginx:rw`

### 3) 为什么不支持通配符证书（*.example.com）？

通配符证书通常要求 DNS-01 验证（HTTP-01 不适用）。本项目当前仅实现 HTTP-01。

## 开发/本地运行

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export PORT=8080
export DATA_DIR=./data
python3 app.py
```

## License

未指定（如需开源协议，可添加 LICENSE）。
