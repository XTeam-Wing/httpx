
<div align="center">
<p>基于 <a href="https://github.com/projectdiscovery/httpx">ProjectDiscovery httpx</a> 的增强版本</p>

</div>

---

## 简介

httpx 是一个快速且多用途的 HTTP 工具包，支持各种定制化，旨在维护结果可靠性并具有高速扫描能力。

## 核心特性

- **简单高效**: 简单的 HTTP 探测器，确保高可靠性
- **端口探测**: 支持 HTTP/HTTPS 探测 (https://example.com:443)
- **智能探测**: 小字典探测，减少噪音
- **URI 模糊器**: VHOST/URI 模糊探测用于主动发现
- **多输出格式**: 支持 JSON/CSV/TXT 输出格式  
- **多探测器**: 支持状态码、内容长度、响应时间、技术检测等
- **技术指纹**: 基于 内置自有指纹规则和外部规则[侦查守卫] 数据集的技术检测
- **截图功能**: 使用无头浏览器进行页面截图
- **反反爬虫**: 智能速率限制和请求随机化

## 安装方式

### Go Install
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### 源码编译
```bash
cd ./httpx
make release
```

## 基本用法

### 单目标探测
```bash
httpx -target example.com
```

### 指纹识别
```bash
httpx -u example.com -td -tr ./FingerprintHub/web-fingerprint/ -fr  -dtp -uit
```

### 批量目标探测
```bash
# 从文件读取目标列表
httpx -l targets.txt

# 管道输入
echo "example.com" | httpx

# 多目标
httpx -u example.com,test.com
```

### 探测模式

#### 基础探测
```bash
# 显示状态码
httpx -sc -l targets.txt

# 显示内容长度
httpx -cl -l targets.txt  

# 显示响应时间
httpx -rt -l targets.txt

# 显示标题
httpx -title -l targets.txt
```

#### 高级探测
```bash
# 截图功能
httpx -ss -l targets.txt

# 综合探测
httpx -sc -cl -rt -title -td -l targets.txt
```

## 输出格式

### JSON 输出
```bash
httpx -json -l targets.txt
```

### CSV 输出  
```bash
httpx -csv -l targets.txt
```

### 自定义输出
```bash
# 输出到文件
httpx -l targets.txt -o results.txt

# 静默模式（只输出 URL）
httpx -silent -l targets.txt
```

## 高级功能

### HTTP 定制
```bash
# 自定义 User-Agent
httpx -H "User-Agent: Custom-Agent" -l targets.txt

# 使用代理
httpx -http-proxy http://proxy:8080 -l targets.txt

# 设置超时
httpx -timeout 10 -l targets.txt

# 最大重定向
httpx -max-redirects 5 -l targets.txt
```

### 速率控制
```bash
# 限制请求速率 (每秒请求数)
httpx -rate-limit 100 -l targets.txt

# 并发控制
httpx -threads 50 -l targets.txt

# 延迟设置
httpx -delay 1s -l targets.txt
```

## 实用示例

### Web 应用发现
```bash
# 发现活跃的 Web 服务
httpx -ports 80,443,8080,8443 -l ips.txt

# 获取页面标题和技术栈
httpx -title -td -l domains.txt
```

### 安全测试
```bash
# 检测 WAF/CDN
httpx -cdn -l targets.txt

# 获取服务器指纹
httpx -server -l targets.txt

# 响应体预览
httpx -bp 200 -l targets.txt
```

### 批量截图
```bash
# 为所有活跃站点截图
httpx -ss -l targets.txt -o screenshots/
```

## 匹配器和过滤器

### 状态码过滤
```bash
# 只显示特定状态码
httpx -mc 200,301,302 -l targets.txt

# 过滤特定状态码  
httpx -fc 404,403 -l targets.txt
```

### 内容长度过滤
```bash
# 过滤特定内容长度
httpx -fs 0,1024 -l targets.txt

# 匹配内容长度范围
httpx -ms 1000-5000 -l targets.txt
```

## 配置文件

创建配置文件 `~/.config/httpx/config.yaml`:

```yaml
# 基础设置
threads: 50
timeout: 10
retries: 2
rate-limit: 100

# 输出设置  
json: true
output: results.json

# 探测设置
status-code: true
content-length: true
title: true
tech-detect: true

# HTTP 设置
follow-redirects: true
max-redirects: 5
```

## 集成使用

### 与其他工具配合
```bash
# 与 subfinder 结合使用
subfinder -d example.com | httpx -title -td

# 与 nmap 结合使用  
nmap -p80,443 --open 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}' | httpx

# 与 nuclei 结合使用
httpx -l targets.txt -silent | nuclei -t exposures/
```

## 输出字段说明

| 字段 | 描述 |
|------|------|
| url | 目标 URL |
| status_code | HTTP 状态码 |
| content_length | 响应内容长度 |
| response_time | 响应时间 |
| title | 页面标题 |
| tech | 检测到的技术栈 |
| server | Web 服务器信息 |
| location | 重定向位置 |
| cdn | CDN/WAF 信息 |

## 常见问题

### Q: 如何提高扫描速度？
A: 调整 `-threads` 和 `-rate-limit` 参数，但注意不要对目标造成过大压力。

### Q: 截图功能不工作？
A: 确保系统安装了 Chrome/Chromium，或使用 `-system-chrome` 参数。

### Q: 如何处理大量目标？
A: 使用 `-silent` 减少输出噪音，配合适当的速率限制。

## 开发和贡献

这是基于 [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) 的 fork 版本，专门为 marshal 项目进行了定制化开发。

### 项目结构
```
ext/httpx/
├── cmd/httpx/          # 主程序入口
├── runner/             # 核心运行逻辑
├── common/             # 通用工具包
├── internal/           # 内部包
└── static/             # 静态资源
```

## 许可证

本项目基于 MIT 许可证开源。原始项目版权归 ProjectDiscovery, Inc. 所有。

---

<div align="center">
<strong>由 XTeam-Wing 维护和增强</strong>
</div> 