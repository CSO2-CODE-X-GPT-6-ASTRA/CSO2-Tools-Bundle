# CSO2 Tools Bundle · CSO2 工具合集

面向 CSO2 本地游玩与房主场景的三个组件：房主管理、BOT 辅助和本地服务端，按需要分别使用。

Three components for local and host-side CSO2 play: host controls, BOT assistance and a local server. Use each component as needed.

**[下载 / Downloads → Release](https://github.com/CSO2-CODE-X-GPT-6-ASTRA/CSO2-Tools-Bundle/releases/latest)** · [发布说明 / Release notes](RELEASE.md)

## 01 · CSO2 Host Tool / 房主工具

| 功能分类 / Category | 中文介绍 | English overview |
| --- | --- | --- |
| 玩家管理 / Players | 玩家列表与批量选择，血量、金钱、无敌、传送及踢出管理。 | Player lists and selection, health, money, invulnerability, teleportation and kick controls. |
| 对局功能 / Match controls | 作弊开关、弹药补充、模型比例、购买限制与武器生成。 | Cheat settings, ammo refill, model scaling, buy restrictions and weapon spawning. |
| 模式与指令 / Modes & commands | 生化模式相关控制、BOT 数量、常用及自定义指令、命令检索。 | Mode-specific controls, BOT counts, preset and custom commands, and command search. |
| 沟通与配置 / Chat & settings | 全体或团队喊话、定时发言、设置保存、日志与中英文界面。 | Global or team chat, scheduled messages, saved settings, logs and a Chinese/English interface. |
| 更新 / Updates | 自动检查、下载更新或打开 Release；新版启动成功后删除 OLD。 | Automatic checks, in-app downloads or the Release page; OLD is removed after successful startup. |

## 02 · CSO2 Bot Tool / BOT 辅助工具

| 功能分类 / Category | 中文介绍 | English overview |
| --- | --- | --- |
| 目标显示 / Target display | 骨骼、血量、距离、视野外方向与危险提示；按模式识别目标。 | Skeletons, health, distance, off-screen directions and threat alerts, with mode-aware targeting. |
| 瞄准与射击 / Aim & fire | 右键瞄准、目标搜索、瞄准平滑、连续自动开火及后坐力补偿。 | Right-button aiming, target search, aim smoothing, continuous automatic fire and recoil compensation. |
| 穿透与战术辅助 / Penetration & movement | 结合配套数据估算墙体穿透，提供高爆手雷预警、躲避及相关辅助。 | Bundled data for wall-penetration estimates, plus HE grenade warnings, evasion and related assistance. |
| 角色与输入 / Character & input | 自身血量锁定、ANTI AIM、鼠标中心锁定与快捷控制。 | Local health locking, ANTI AIM, cursor confinement and shortcut controls. |
| 运行与配套 / Runtime & resources | 游戏连接、显示与配置管理；随包提供射击穿透数据和 Frida 依赖。 | Game connection, display and configuration controls; penetration data and the Frida runtime are included. |
| 更新 / Updates | 检查脚本及两个配套文件夹的更新；支持下载替换、OLD 备份和 Release 手动更新。 | Checks the script and both resource folders; supports download-and-replace updates, OLD backups and manual updates via Release. |

## 03 · CSO2 Local Master Server / 本地主服务端

| 功能分类 / Category | 中文介绍 | English overview |
| --- | --- | --- |
| 本地启动 / Local launch | 客户端目录扫描与选择、本地账号自动登录、游戏和服务端启动。 | Client discovery and selection, local account login, and game/server launch controls. |
| 服务与存档 / Server & saves | 服务状态查看、存档保存、停止服务和日志；关闭面板后服务可继续运行。 | Server status, save controls, shutdown and logs; the server can continue after the panel closes. |
| 单人玩法 / Solo play | 模式与地图选择，以及生化、恶灵选择规则和作弊开关。 | Mode and map selection, zombie/ghost selection rules and cheat settings. |
| 显示与维护 / Display & maintenance | 分辨率、窗口与低内存设置，模型加载补丁和 ReShade 恢复入口。 | Resolution, window and low-memory settings, plus model-loading patch and ReShade restoration tools. |
| 整合与更新 / Packaging & updates | 一个 PYW 加一个中英文依赖文件夹；自动更新 PYW，重启成功后删除 OLD，或打开 Release 手动更新。 | One PYW plus one bilingual dependency folder; update the PYW and remove OLD after a successful restart, or open Release for manual updates. |

相关项目参考 / Related project: **[CSO2 Master Server — lateleite](https://github.com/lateleite/cso2-master-server)**。随包服务端的原作者信息与许可保留在 [server/LICENSE](<CSO2 Local Master Server/Dependencies 外部依赖/server/LICENSE>)。 / The bundled server retains its original attribution and license in that file.

## 运行与下载 / Getting started

使用 Windows 和带 Tk 的 Python；BOT Tool 需要 **64 位 Python 3.11 或更高版本**。游戏客户端需自行准备，具体功能取决于客户端版本、模式和房主权限。7Z 请完整解压，保留 PYW 与配套文件夹的位置关系。

Use Windows and Python with Tk; BOT Tool requires **64-bit Python 3.11 or later**. Provide a compatible game client. Feature availability depends on the client version, game mode and host permissions. Extract each 7Z fully and keep its PYW beside the supplied folders.

发布包不包含原使用者的账号、密码、控制令牌、存档和历史日志。 / Release packages exclude the original user's accounts, passwords, control tokens, saves and historical logs.

**最后更新 / Last updated: 2026-10-09 (UTC+8)**
