<details open>
<summary><strong>English</strong></summary>

### Install [Python from the official website](https://www.python.org/downloads/) before using these tools

- **CSO2 Host Tool** — Player management, match settings and commands.

  Validation: 102 regression checks and 48 Chinese/English layout checks passed. Live match behavior still requires in-game confirmation.

  This refresh keeps **v1.0.0**. Download `cso2-host-tool.pyw` again to get the current build. The download contains empty personal settings.

  <dl><dd>

  <details>
  <summary>Previous updates</summary>
  <dl><dd>

  **2026-11-20:**

  <p>Added bot skin selection.<br>CT and T can each use random female or male characters. Each bot draws its own skin every round.</p>

  **Updated on 2026-10-10:**

  - Heroes: continuous monster clearing with an adjustable countdown, temple protection, fast wave completion, wave selection and an option to skip preparation periods.
  - All-player attack and health upgrades, custom player damage against monsters, and monster target exclusion.
  - Player/model selection popup with individual dropdowns, batch selection and seven HERO preset buttons.
  - Chinese/English Heroes controls and messages; the model popup opens centered, and windows can be dragged partly off screen.
  - Restored Heroes controls and weapon spawning when the host needs to enable `sv_cheats` first.

  </dd></dl>
  </details>

  <details open>
  <summary><strong>2026-11-26:</strong></summary>
  <dl><dd>

  - Set up commands, weapon spawning, chat, Heroes and ZETA actions before joining a match; queued actions wait for the matching game state. Commands support once in the next match, every match, or disabled.
  - Apply HP, money, locks and invulnerability automatically to yourself, your teammates or both teams. Ghost visibility can also be configured before joining.
  - Chat now has separate entries with length counters, add/remove controls and ordering. Pending messages follow the selected channel; edited or deleted entries are removed from timers and saved settings.
  - ZETA adds mutation capacity, mutation points and a preset for the next native mutation attempt. Skills and BOT skins use in-game names with searchable names, codes and IDs.
  - Clearer Chinese/English menus, checkmarks for selected options, stable dropdown arrows, scrolling only inside open dropdowns, and wider default layouts with complete waiting-state labels.
  - Fixed malformed commands interrupting polling, lost shutdown requests when the queue is full, next-match actions firing early after restart or before the first round snapshot, and already-owned skills being reported as newly acquired.

  </dd></dl>
  </details>

  </dd></dl>

- **CSO2 Bot Tool** — Target display, aiming, firing and penetration assistance.

  <dl><dd>

  <details>
  <summary>Previous updates</summary>
  <dl><dd>

  **Updated on 2026-11-05:**

  - Automatically restores missing or damaged Frida runtime files, with background checks and clear error messages.
  - Fixes the countdown policy's “Apply once” click handling and shows progress, success or failure in the popup.

  </dd></dl>
  </details>

  <details open>
  <summary><strong>Updated on 2026-11-15:</strong></summary>
  <dl><dd>
  <p>Improved aiming speed and compressed logs.<br>The non-host magic bullet feature is for fun only. Do not enable it for serious matches; it is less accurate than auto-aim.</p>
  </dd></dl>
  </details>

  </dd></dl>

- **CSO2 Local Master Server** — Local launch, solo play and save management.

Local server reference: [CSO2 Master Server — lateleite](https://github.com/lateleite/cso2-master-server).

**Last updated: 2026-11-26**

</details>

<details open>
<summary><strong>中文</strong></summary>

### 使用前请先从 [Python 官网](https://www.python.org/downloads/) 下载并安装 Python

- **CSO2 Host Tool · 房主工具** — 玩家管理、对局设置与指令。

  验证：102 项回归和 48 次中英文布局检查通过；真实对局效果仍待实机确认。

  本次保持 **v1.0.0**，请重新下载 `cso2-host-tool.pyw` 获取新版。下载文件中的个人设置为空。

  <dl><dd>

  <details>
  <summary>历史更新</summary>
  <dl><dd>

  **2026-11-20 更新：**

  <p>新增 BOT 换皮肤机制。<br>CT 和 T 的整队下拉框均可选择「全部随机女性角色」或「全部随机男性角色」，每个 BOT 每回合独立抽取。</p>

  **2026-10-10 更新：**

  - 洛奇英雄传：持续清怪与可调倒计时、神殿保护、快速完成当前波、指定波次，以及跳过准备等待期。
  - 全体玩家攻击力与生命强化、玩家对怪物的自定义伤害，以及怪物不攻击玩家。
  - 玩家与模型对应弹窗，支持逐人下拉选择、批量选择及七个 HERO 模型快捷按钮。
  - 补齐 HEROES 控件和提示的中英文；模型弹窗打开时居中，窗口可拖到屏幕边缘外隐藏一部分。
  - 修复洛奇按钮不可用，以及需要先开启 `sv_cheats` 时无法刷枪的问题。

  </dd></dl>
  </details>

  <details open>
  <summary><strong>2026-11-26 更新：</strong></summary>
  <dl><dd>

  - 指令、地面生成、喊话、洛奇英雄传和生化 ZETA 操作可在进房前设置，等待对应游戏状态后执行。指令支持“新对局仅一次”“每局发送”和“停用”。
  - 血量、金钱、锁定和无敌支持对本人、队友或敌我双方自动生效；幽灵显形也可在进房前预设。
  - 喊话拆分为独立条目，增加长度统计、新增、删除和排序。待发消息跟随所选频道；编辑或删除的内容会同步更新定时器及保存设置。
  - ZETA 增加技能数量上限、突变点数和下一次原生突变的指定技能预设。技能与 BOT 角色使用游戏内名称，支持按名称、代号及编号搜索。
  - 改善中英文菜单、普通选中对勾、下拉箭头和滚轮行为；仅展开下拉后滚轮才切换列表。默认窗口加宽，等待状态文案完整显示。
  - 修复错误引号中断轮询、队列满时关闭请求丢失、重启或首个回合快照导致下一局任务提前发送，以及已有技能误报为本次取得的问题。

  </dd></dl>
  </details>

  </dd></dl>

- **CSO2 Bot Tool · BOT 辅助工具** — 目标显示、瞄准射击与穿透辅助。

  <dl><dd>

  <details>
  <summary>历史更新</summary>
  <dl><dd>

  **2026-11-05 更新：**

  - Frida 依赖文件缺失或损坏时自动恢复，后台持续检查并明确提示错误。
  - 修复倒计时策略“仅处理本次”的点击处理，弹窗显示处理进度及成功或失败结果。

  </dd></dl>
  </details>

  <details open>
  <summary><strong>2026-11-15 更新：</strong></summary>
  <dl><dd>
  <p>改进瞄准速度，对日志进行压缩。<br>非房主魔法子弹功能仅娱乐，如果认真对局请勿启用，准度不如自动瞄准。</p>
  </dd></dl>
  </details>

  </dd></dl>

- **CSO2 Local Master Server · 本地主服务端** — 本地启动、单人玩法与存档管理。

本地端相关项目：[CSO2 Master Server — lateleite](https://github.com/lateleite/cso2-master-server)。

**最后更新：2026-11-26**

</details>
