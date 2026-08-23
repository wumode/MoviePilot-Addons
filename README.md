# MoviePilot-Addons

MoviePilot 自定义插件扩展仓库，提供适用于 MoviePilot 的各类增强插件与功能扩展。

## 📦 插件列表

### MoviePilot V3 插件 (`plugins.v3`)

| 插件名称 | 插件标识 | 当前版本 | 适用系统版本 | 简介 |
| :--- | :--- | :--- | :--- | :--- |
| **Clash Rule Provider** | `ClashRuleProvider` | `v3.0.0` | `>=3.0.0` | 为 Meta (Mihomo) 内核生成定制配置与规则集，支持大洲国家分组、可见性过滤等 |
| **WebDAV存储** | `WebdavStorage` | `v1.0.0` | `>=3.0.0` | 为 MoviePilot 提供 WebDAV 协议存储支持，实现云盘与远端文件管理 |

### MoviePilot V2 历史插件 (`plugins.v2`)

| 插件名称 | 插件标识 | 当前版本 | 简介 |
| :--- | :--- | :--- | :--- |
| **Best Cloudflare IP** | `CloudflareSpeedTestForClash` | `v1.0` | 基于 CloudflareSpeedTest 进行 IP 优选，并同步至 Clash Rule Provider |

---

## 🔧 插件详细说明

### 1. Clash Rule Provider (V3)

生成适用于 [Meta Kernel (Mihomo)](https://github.com/MetaCubeX/mihomo) 的定制配置，提供灵活便捷的规则与分流管理：

- **即时生效与通知**：即时通知 Clash 刷新规则集合。
- **节点自动分组**：支持按大洲、国家/地区对代理节点自动分组。
- **出站与覆写**：支持覆写出站代理、置顶规则与规则集合生成。
- **规则集与提示**：内置 GEO 规则输入提示，支持 [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) 规则集合。
- **高级可见性控制**：支持基于 Python 条件表达式动态控制代理组、规则和节点的显示与隐藏。
- **Vue 远程组件**：支持前端交互界面，前端工程详见 [ClashRuleProvider-Remote](https://github.com/wumode/ClashRuleProvider-Remote)。
- 更多详细配置请查阅：[Clash Rule Provider 说明文档](plugins.v3/clashruleprovider/README.md)。

### 2. WebDAV存储 (V3)

为 MoviePilot 存储体系扩展 WebDAV 协议支持：

- **存储集成**：通过劫持存储操作接口，无缝接入 MoviePilot 文件管理与整理体系。
- **完整操作支持**：支持目录浏览、文件上传/下载、移动、重命名、删除与目录创建。
- **快照与对账**：支持目录快照与增量对账，适配多层级文件结构。

### 3. Best Cloudflare IP (V2)

修改自 [thsrite](https://github.com/thsrite) 的 Cloudflare IP 优选插件：

- 基于 [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 定时测速优选。
- 支持 IPv4 / IPv6 优选及附加自定义 IP。
- 自动将优选结果同步至 Clash Rule Provider。
- 支持运行通知与执行周期定时任务。

---

## 🚀 安装与使用

在 MoviePilot 中添加本仓库作为第三方插件源：

1. 打开 MoviePilot Web 界面。
2. 进入 **设定** -> **插件** -> **插件市场** / **插件源**。
3. 添加本仓库地址：
   ```text
   https://github.com/wumode/MoviePilot-Addons
   ```
4. 保存后刷新插件市场，即可在市场中搜索并安装所需插件。

---

## 📚 开发与文档

- [V3 插件开发指南](docs/Plugin_Development.md)
- [仓库维护与发布指南](docs/Repository_Guide.md)
- [V2 插件迁移至 V3 说明](docs/V3_Plugin_Adaptation.md)
- [V3 插件 API 响应适配指南](docs/V3_API_Response_Adaptation.md)
- [常见问题解答 (FAQ)](docs/FAQ.md)

---

## 🔗 相关链接

- [MoviePilot 官方仓库](https://github.com/jxxghp/MoviePilot)
- [MoviePilot 官方插件市场](https://github.com/jxxghp/MoviePilot-Plugins)
- [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)
- [Mihomo (Meta 内核)](https://github.com/MetaCubeX/mihomo)

---

## 📄 开源许可

本项目遵循 [GPL-3.0 License](LICENSE) 开源协议。
