# 疏狂的博客

使用自己的 [Flavor 主题](https://github.com/N1etzsche0/flavor)与 Hugo Extended 构建，默认发布到 **GitHub Pages**。保留 Flavor 的浅色 / 蓝黑深色、文章目录、代码复制、友链和 Pagefind 本地全文搜索。

## 本地运行

需要 Node.js 22+、Git，以及 `tar`。Linux x64 / arm64 和 Windows x64 首次运行会自动下载 `.hugo-version` 指定的 Hugo Extended 到项目的 `.tools/`，并校验官方 SHA-256；不修改系统安装。其他平台先从 [Hugo 官方发行页](https://github.com/gohugoio/hugo/releases/tag/v0.163.1)安装同版本 Extended。

```bash
git clone --recurse-submodules https://github.com/N1etzsche0/N1etzsche0.github.io.git
cd N1etzsche0.github.io
npm ci
npm run dev
```

打开 `http://localhost:1313/`。如果克隆时没有拉取主题，先执行 `git submodule update --init --recursive`。

开发预览包含草稿。完整搜索需要构建后预览：

```bash
npm run build
npm run check
npm run preview
```

`npm run test:browser` 使用本机已安装的 Chromium / Chrome 验证搜索、主题切换、移动菜单、目录和页面链接。可用 `CHROMIUM_PATH` 指定浏览器路径，截图保存在 `.artifacts/`。

## 写文章

在 `content/post/文章名/index.md` 写 Markdown，图片放在同一目录。示例：

```yaml
---
title: "新文章"
slug: "new-post"
date: 2026-10-20T10:00:00+08:00
draft: true
tags: ["笔记"]
categories: ["技术笔记"]
description: "文章摘要"
---
```

准备发布时改为 `draft: false`，同时确保日期不是未来时间。`sticky: true` 可以置顶。

- 基本信息、导航、头像：`hugo.toml`。
- 关于页：`content/page/about/index.md`。
- 友链：`data/friends.yaml`。
- 站点图标：`static/favicon.svg`。
- 初始两篇文章用于演示，可直接修改或删除。

加密文章沿用主题的 `themes/flavor/scripts/encrypt.sh`；明文只放在已忽略的 `content/private/`。

## 主题调整

站点沿用 Flavor 原有的浅色纸白、深色蓝黑和导航渐变，配色变量由主题子模块统一管理。视觉与交互调整保存在项目根目录：`assets/css/site.css` 管理间距、排版与手机端布局；`assets/js/theme-toggle.js` 管理主题偏好和导航菜单；`layouts/index.html` 与 `layouts/page/about.html` 分别管理首页和关于页布局。关于页正文仍在 `content/page/about/index.md` 编辑，侧栏自动读取 `hugo.toml` 中的姓名、头像、简介与社交链接。

主题偏好保存在当前浏览器中；未手动选择时跟随系统。搜索支持 `Ctrl/⌘ + K` 打开、`Esc` 或关闭按钮退出；手机导航支持点菜单外区域或按 `Esc` 收起。

文章页自动显示阅读进度、段落标题定位链接，以及带语言提示的代码复制工具栏，无需修改 Markdown。`assets/js/article.js`、`code-copy.js` 与 `toc.js` 分别管理这些功能；目录在手机和平板上以浮层打开，支持键盘操作、点击遮罩关闭及选中章节后返回正文，桌面端保留目录与正文并排阅读。

## GitHub Pages 发布

博客正式地址为 <https://shukuang.fyi/>，源码与发布仓库仍为 `N1etzsche0.github.io`。GitHub 免费方案下使用公开仓库即可，不需要购买服务器。

在仓库 **Settings → Pages → Source** 选择 **GitHub Actions**。之后推送到 `main` 会自动构建、校验并发布；Pull Request 只构建检查。

```bash
git add .
git commit -m "Update blog"
git push
```

工作流读取 Pages 返回的实际 URL，支持自定义域名和 `/blog/` 等项目路径。若使用 HTTPS 的 GitHub OAuth 登录，推送 `.github/workflows/` 需要凭据具有 `workflow` scope；可使用 `gh auth refresh -h github.com -s workflow` 完成授权。

自定义域名已在 GitHub Pages 设置中设为 `shukuang.fyi`，`hugo.toml` 的 `baseURL` 使用同一域名。GitHub Actions 发布依赖仓库的 Pages 设置，不读取 `CNAME` 文件。以后更换域名时需要同时更新 Pages 设置、`hugo.toml` 和工作流中的备用地址；构建环境也可以通过 `HUGO_BASEURL` 覆盖站点地址。

## 加载优化

参考 baozongwi.xyz 的实际资源组织方式，本站采用：

- 完整静态 HTML，无数据库和运行时框架。
- 系统中文字体；导航字体随站点托管，不依赖第三方字体 CDN。
- CSS / JS 压缩并生成内容哈希文件名；文章目录、代码复制、图片灯箱只在对应页面加载。
- Pagefind 搜索索引在打开搜索框时加载，搜索内容保留在浏览器本地。
- 默认关闭欢迎遮罩和打字动画，首屏直接呈现正文。
- 文章目录中的 PNG / JPEG 等光栅图片由主题在构建时转 WebP；大图提供响应式尺寸。不要将正文图片放在外部图床来依赖运行时跨域请求。
- 生产构建检查所有站内链接与资源，并检查首页 / 样式的 gzip 体积预算。

GitHub Pages 自行控制 HTTP 缓存头，构建产物中的 `_headers` **只对 Cloudflare Pages 生效**。不能通过该文件改变 GitHub Pages 的缓存策略。

大陆访问速度取决于运营商、域名与跨境线路，本地构建或海外测速不能证明大陆加载速度。

### Cloudflare DNS 与 CDN

域名 `shukuang.fyi` 使用 Cloudflare 免费 DNS，当前记录均为 **DNS-only（灰云）**，网站由 GitHub Pages 提供，已启用强制 HTTPS。根域名配置 GitHub Pages 官方的 4 条 A 和 4 条 AAAA 记录，`www` 的 CNAME 指向 `n1etzsche0.github.io`。Cloudflare SSL/TLS 预设为 **Full (strict)**，仅在开启代理时生效。

2026-10-20 对同一批节点完成三轮直连、三轮代理测试，并补做固定 IP、保留域名与有效 TLS 的对照以排除旧 DNS 缓存。固定 IP 对照中的 15 个在线大陆节点，GitHub 成功 12 个、成功请求中位耗时 292 ms；Cloudflare 成功 7 个、中位耗时 958 ms。因此当前保留直连。该结果只代表此次 IPv4 HTTPS 首页请求的样本，不代表全国可用率或完整页面加载时间。原始结果保存在本地 `.artifacts/domain-2026-10-20/`。

以后若重试代理，先确认 GitHub Pages 源站证书有效，再从实际读者所在的电信 / 联通 / 移动网络比较效果。已保留一条停用的公开页面缓存规则，重启时可让 CDN 与浏览器沿用源站 `Cache-Control`（当前 `max-age=600`）；文章发布后最多可能等待约 10 分钟刷新，也可在 Cloudflare 清理对应 URL 的缓存。免费 Cloudflare 不包含大陆节点；购买普通 Pro 套餐也不等于接入其中国网络。若 GitHub 证书续签出现问题，临时关闭代理，核对域名的 DNS 与证书状态后恢复。

若以后切换为 Cloudflare Pages，导入同一 GitHub 仓库，生产分支 `main`，构建命令 `npm run build`，输出目录 `public`，Node 版本 `22`。设置 `HUGO_BASEURL=https://你的正式域名/`；未设置时构建脚本使用 Cloudflare 提供的 `CF_PAGES_URL`。无需 Functions / Workers，也无需付费套餐。

可选 `_headers` 对带哈希文件名的 CSS / JS 使用一年缓存，固定文件名的字体只缓存一天，搜索索引要求重新验证，避免更新后继续搜索旧内容。HTML 使用平台默认缓存策略。

### 更新主题

```bash
git submodule update --remote --merge themes/flavor
npm run build
npm run check
```

主题保持原样，站点定制集中在根目录的 `layouts/` 和 `assets/`。升级时需要核对同名模板的改动，再提交更新后的主题版本指针。

参考文档：[Hugo → GitHub Pages](https://gohugo.io/host-and-deploy/deploy-to-github-pages/)、[GitHub Pages 自定义域名](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)、[Cloudflare Pages 缓存头](https://developers.cloudflare.com/pages/configuration/headers/)、[Cloudflare 中国网络](https://developers.cloudflare.com/china-network/)。
