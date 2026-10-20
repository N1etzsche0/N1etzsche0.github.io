---
title: "写作工作流：从 Markdown 到博客"
slug: "writing-with-hugo"
date: 2026-10-20T09:00:00+08:00
description: "一篇用于熟悉博客的入门笔记：文章、图片、预览与发布。"
categories: ["技术笔记"]
tags: ["Hugo", "Markdown"]
stale: false
---

这是一篇入门笔记，也是一份给自己的写作备忘录。

## 新建一篇文章

文章和配图放在同一个目录，后续迁移和整理会方便一些。目录中的 `index.md` 是正文，其他文件是它的附件。

```text
content/post/my-note/
├── index.md
└── screenshot.png
```

文章开头写上标题、日期、标签等信息。草稿设置 `draft: true`，准备发布时再改成 `false`。

```yaml
---
title: "我的新笔记"
slug: "my-note"
date: 2026-10-20T16:00:00+08:00
draft: true
tags: ["笔记"]
---
```

## 预览与构建

```bash
npm ci
npm run dev
```

保存 Markdown 后，浏览器会自动刷新。正式构建会生成静态页面和本地搜索索引：

```bash
npm run build
npm run preview
```

## 插入图片

将图片放在文章目录里，使用相对路径引用。构建时，主题会为支持的光栅图片生成 WebP 版本，较大的图片会提供响应式尺寸。

```markdown
![图片说明](screenshot.png)
```

## 发布前

检查标题、链接和配图，再移除草稿标记。正文里的细节可以慢慢修订，但每次修改都值得保留在版本记录中。
