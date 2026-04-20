# LM Studio Translate Web

一个本地翻译网页项目，直接调用你电脑上的 `LM Studio` OpenAI 兼容接口。

这个项目的设计重点不是“能翻译就行”，而是两件事：
- 翻译内容默认不允许发到外网
- 操作尽量短路径，适合频繁复制、粘贴、翻译

## 隐私与联网边界

这个项目默认只允许把请求发到本机回环地址：
- `127.0.0.1`
- `localhost`
- `::1`

也就是说，后端会拒绝这类地址：
- 公网 IP
- 局域网 IP
- 任意远程域名

同时，程序发请求时显式关闭了系统代理继承：
- `requests.Session().trust_env = False`

这样做的目的，是避免请求被环境变量里的代理或系统代理转发出去。

当前实现下，翻译文本的流向是：
1. 浏览器把文本发给本机 Flask 服务
2. Flask 服务把文本发给本机 `LM Studio`
3. `LM Studio` 本地模型返回译文
4. 结果回到当前浏览器页面

默认不会做这些事：
- 不会把翻译文本发送到远程 API
- 不会把翻译历史写入数据库
- 不会把原文和译文持久化到项目文件里

仍然要知道的边界：
- 文本会短暂存在于当前浏览器页面内存和 Python 进程内存中
- 如果你自己把项目改成远程 `base_url`，后端现在会直接拒绝
- 如果 `LM Studio` 自己加载的是云端模型或云插件，那是 `LM Studio` 侧的问题，不是这个项目主动外传

## 功能

- 读取 `LM Studio` 当前已加载模型列表
- 手动填写模型名或从列表切换模型
- 一键粘贴原文
- 一键复制原文
- 一键复制译文
- 翻译时显示进度条和状态
- 保存本地配置

## 默认接口

```text
http://127.0.0.1:1234/v1
```

## 运行要求

- 已安装 `Python`
- 已安装并启动 `LM Studio`
- `LM Studio` 已开启本地 OpenAI 兼容服务
- 至少已加载一个可用于文本生成/翻译的模型

建议优先使用已经验证兼容的模型：
- `translategemma-12b-it`

某些模型如果在 `LM Studio` 里自带的 prompt template 不兼容，可能会返回 `400` 或 `500`。这不是网页前端问题，而是模型模板本身的问题。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

## 启动

```powershell
.\start.ps1
```

也可以直接双击：

```text
start.bat
```

启动后默认地址：

```text
http://127.0.0.1:7870/
```

## 使用说明

1. 打开 `LM Studio`
2. 加载本地模型
3. 确认本地接口能访问 `http://127.0.0.1:1234/v1/models`
4. 启动本项目网页
5. 点击“刷新模型”
6. 选择模型或手动填写模型名
7. 粘贴原文后点击“开始翻译”

## 常见问题

### 1. 提示无法连接到 `127.0.0.1:1234`

说明 `LM Studio` 没启动，或者本地 API 服务没开。

检查：
- `LM Studio` 是否正在运行
- 本地服务端口是不是 `1234`
- `LM Studio` 里是否已启用 OpenAI 兼容接口

### 2. 提示只允许连接本机 LM Studio

这是刻意加的限制，不是 bug。

目的是确保翻译文本不会被这个项目发到外部网络。

### 3. 有些模型能列出来，但翻译时报错

说明模型可能已加载，但它的 prompt template 和当前请求格式不兼容。

优先换成已验证模型，例如：
- `translategemma-12b-it`

## GitHub 发布

当前目录最初不是 Git 仓库。

如果你要发布到 GitHub，常规步骤是：

```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <你的 GitHub 仓库地址>
git push -u origin main
```

如果你本机已经配置好了 `git` 凭据或 `GitHub CLI`，可以直接推送。否则需要你先完成 GitHub 登录或告诉我仓库地址。
