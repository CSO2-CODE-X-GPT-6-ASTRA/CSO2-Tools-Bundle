<details open>
<summary><strong>English</strong></summary>

### Install [Python from the official website](https://www.python.org/downloads/) before using these tools

- **CSO2 Host Tool** — Player management, match settings and commands.

  **2026-11-20:** Added bot skin selection in the local build. The current download does not include this feature yet.

  <details>
  <summary>Updated on 2026-10-10</summary>

  - Heroes: continuous monster clearing with an adjustable countdown, temple protection, fast wave completion, wave selection and an option to skip preparation periods.
  - All-player attack and health upgrades, custom player damage against monsters, and monster target exclusion.
  - Player/model selection popup with individual dropdowns, batch selection and seven HERO preset buttons.
  - Chinese/English Heroes controls and messages; the model popup opens centered, and windows can be dragged partly off screen.
  - Restored Heroes controls and weapon spawning when the host needs to enable `sv_cheats` first.

  Validation: the published source matches the build that passed 38 scoped checks. No full CHECK was run; live gameplay still needs confirmation, including special Boss attacks already in progress.

  This refresh keeps **v1.0.0**. If you already have v1.0.0, download `cso2-host-tool.pyw` again; the current updater only offers higher version numbers. The download contains empty personal settings.

  </details>

- **CSO2 Bot Tool** — Target display, aiming, firing and penetration assistance.

  <details>
  <summary>Previous Bot Tool updates</summary>

  **Updated on 2026-11-15:**

  Improved aiming speed and compressed logs.

  The non-host magic bullet feature is for fun only. Do not enable it for serious matches; it is less accurate than auto-aim.

  **Updated on 2026-11-05:**

  - Automatically restores missing or damaged Frida runtime files, with background checks and clear error messages.
  - Fixes the countdown policy's “Apply once” click handling and shows progress, success or failure in the popup.

  </details>

- **CSO2 Local Master Server** — Local launch, solo play and save management.

Local server reference: [CSO2 Master Server — lateleite](https://github.com/lateleite/cso2-master-server).

**Last updated: 2026-11-20**

</details>

<details open>
<summary><strong>中文</strong></summary>

### 使用前请先从 [Python 官网](https://www.python.org/downloads/) 下载并安装 Python

- **CSO2 Host Tool · 房主工具** — 玩家管理、对局设置与指令。

  **2026-11-20 更新：** 本地新版新增 BOT 换皮肤机制。当前下载包尚未包含此功能。

  <details>
  <summary>2026-10-10 更新</summary>

  - 洛奇英雄传：持续清怪与可调倒计时、神殿保护、快速完成当前波、指定波次，以及跳过准备等待期。
  - 全体玩家攻击力与生命强化、玩家对怪物的自定义伤害，以及怪物不攻击玩家。
  - 玩家与模型对应弹窗，支持逐人下拉选择、批量选择及七个 HERO 模型快捷按钮。
  - 补齐 HEROES 控件和提示的中英文；模型弹窗打开时居中，窗口可拖到屏幕边缘外隐藏一部分。
  - 修复洛奇按钮不可用，以及需要先开启 `sv_cheats` 时无法刷枪的问题。

  验证：发布源码与通过 38 项专项检查的版本一致。未运行全量 CHECK；游戏实际效果仍待确认，包括特殊 Boss 已开始的攻击动作。

  本次保持 **v1.0.0**。已安装 v1.0.0 的用户请重新下载 `cso2-host-tool.pyw`，当前自动更新只提示更高版本号。下载文件中的个人设置为空。

  </details>

- **CSO2 Bot Tool · BOT 辅助工具** — 目标显示、瞄准射击与穿透辅助。

  <details>
  <summary>BOT 工具历史更新</summary>

  **2026-11-15 更新：**

  改进瞄准速度，对日志进行压缩。

  非房主魔法子弹功能仅娱乐，如果认真对局请勿启用，准度不如自动瞄准。

  **2026-11-05 更新：**

  - Frida 依赖文件缺失或损坏时自动恢复，后台持续检查并明确提示错误。
  - 修复倒计时策略“仅处理本次”的点击处理，弹窗显示处理进度及成功或失败结果。

  </details>

- **CSO2 Local Master Server · 本地主服务端** — 本地启动、单人玩法与存档管理。

本地端相关项目：[CSO2 Master Server — lateleite](https://github.com/lateleite/cso2-master-server)。

**最后更新：2026-11-20**

</details>
