# 多视角并行实验 · Case Study

> huashu-md-html v2.0 launch film 项目 · 2026-05-11
> 6 位艺术家视角的 director's notes + HTML + 关键帧实验
>
> **策略注记**：本 skill 不 spawn subagent（SKILL 限制 CHILD_AGENTS_MAX: 0）。下文原实验中的并行步骤，现已改为依次 inline 执行；记录里的并行耗时与失败数据是历史证据，不是操作指引。

---

## 背景

用户要求「为 huashu-md-html v2.0 制作 30 秒升级宣传片」时，主线程先产出了 v5 基线（Anthropic / Penguin Classics 出版社品位）。但用户认为可以做得更好，给了 critical instruction：

> 「调用不同的 subagent 分别再去生成 6 个全然不同的表达方式和视觉设计的版本。你可以试试启用不同的导演和艺术家。然后全都完成后，再评判审校。」

这是首次系统化的「多视角并行 director's notes」实验，验证了一套可复用的工作流。

---

## 6 个视角的选择逻辑

不要随便选 6 个 designer——他们必须**视觉差异度极高**，避免趋同。

最终选择的 6 个视角（含选择理由）：

| 视角 | 流派 | 美学锚点 | 跟其他视角的差异 |
|------|------|---------|----------------|
| **v5 基线** | 现代出版社 | Anthropic 赤陶橙 + Penguin Classics 衬线 + Vignelli grid | 安全的「品位」选择 |
| **v5a Wes Anderson** | 电影章节美学 | The French Dispatch 杂志感 + 1960 Olivetti 工业目录 | 对称构图 + 章节卡片 + 装饰边框 |
| **v5b Saul Bass** | 60s 影片标题艺术 | cut-paper + Trajan caps + 流动几何 | 剪纸 silhouette + 大字 + 强对角线 |
| **v5c 王家卫** | 港式新浪潮 | 《花样年华》《2046》 letterboxing + 中文衬线 | 慢拍 + 雾化光晕 + 中文为主 |
| **v5d Massimo Vignelli** | 1970 现代主义 | Knoll identity manual + NYC Subway map | 严格 grid + 3 色铁律 + 拒绝装饰 |
| **v5e Kenya Hara** | 极简日式 | MUJI 海报 + 《白》 | 留白哲学 + 无 chrome + ma 间 |
| **v5f Yayoi Kusama** | 装置艺术 | Infinity Mirror Rooms + Polka Dot Obsession | obsessive 重复 + 单一强色 + 圆点 |

**选择原则**：
1. **3 个不同地理文化**（西方电影 / 日本设计 / 港式中文）
2. **3 个不同年代**（1960s / 1970s / 2010s+）
3. **3 个不同载体**（电影 / 平面设计 / 装置艺术）
4. **每个都有「跟训练语料里通用 SaaS 美学完全相反」的视觉签名**

---

## 实施流程

### Step 1 · 为每个视角写独立 brief（约 15 分钟）

每个 brief 包含 8 个固定字段：

```
1. 项目背景（同一份）
2. 必读参考（同一份 v5-director-notes.md 作方法论模板）
3. 你要做的事（4 项交付清单）
4. 该艺术家 DNA（核心字段 6 项）：
   - 色板（具体 HEX）
   - 字体（具体名字 + 替代方案）
   - 视觉语言（核心几条）
   - 招牌元素（identifiable signatures）
   - 节奏（区别其他视角）
   - 反 AI slop 强化版（在该风格语境下的禁区）
5. 30 秒结构参考（4-6 个 shot 草拟）
6. destination cards 设计要求（保持真实可读）
7. 关键约束（30s / 1920×1080 / file:// / Google Fonts CDN）
8. 输出验证清单 + 完成报告格式
```

**关键**：每个 brief 必须强调「**不要重复 v5 的美学**」——否则前一版会被 v5 director-notes 影响而趋同。

### Step 2 · 依次 inline 产出 6 个视角（不 spawn subagent）

每个视角：只读自己的 brief → 独立产出完整版本（spec + HTML + 关键帧）→ 写入项目目录 → 再开下一个视角。前一版的产出不作为下一版的输入。

逐个完成，不做后台运行。

### Step 3 · 视角之间的间隙工作

每完成一个视角、开下一个之前可做：

- 修主线程的 v5 基线 bug
- 写 review framework（每个版本要打的分维度 / Q&A）
- 沉淀方法论到 skill（这正是这份 case study 的来源）
- 准备 final summary 文档骨架

### Step 4 · 失败处理

实战观测：6 个视角中约 1 个会因网络或 token 超限中断（Bass 首轮 socket error）。处理：

1. 视角完成后**立即检查**其输出文件夹
2. 缺少关键交付物 → 重做该视角（同样 brief，可标注「上次失败，请重新执行」）
3. 部分完成（如有 html 没截图）→ 补截图（`legion script designer/verify`），不重做该视角

### Step 5 · 6 版本完成后系统审校

审校 framework（5 维度 + 3 顶层问 + use case 分配）：

```
5 维度评分（每维 1-10）：
- Distinctiveness 视觉差异化
- Coherence 美学一致性
- Anti-slop 反 AI slop 执行
- Story arc 节奏与故事弧
- Pause-and-look 细节密度

3 顶层问：
- Q1 截图分享？（能在社交平台触发暂停）
- Q2 记一句话？（能留下命题级记忆）
- Q3 跨时代？（5 年后回看不显廉价）

use case 分配（按平台和受众）：
- 公众号 / X / B 站 / 朋友圈 / Dribbble / 客户演示 / 私域 / ...
```

样本及其同目录 REVIEW.md 未随本包发布。

---

## 实验产出（事实）

### 文档量

- v5 基线 director-notes：11500 字
- 6 视角 director-notes 各 4000-12000 字
- 总文档量：约 55000-70000 字
- 5 大部分结构齐全：6/6 版本

### HTML 实施

- 每版独立 animation.html，30 秒，1920×1080
- 文件大小 28-74KB
- 全部 file:// 可打开（不依赖 server）

### 关键帧

- 每版 10-18 张 PNG，覆盖完整 30 秒故事弧
- 总截图量：80+ 张
- 平均每张 PNG 大小：100-200KB

### 时长

- 每个视角约 12-15 分钟（历史 duration_ms 记录）
- 视角间隙的 idle work（修 v5 + 写方法论）：同期完成（历史记录）
- 整体「从启动 6 视角到所有 deliverable 到位」：约 60 分钟

---

## 关键洞察（写给 huashu-design 的未来用户）

### 洞察 1 · 「先写万字 director's notes」方法论**完全 reproducible**

6 个 subagent 都按 5 大部分结构产出了 4000-12000 字的完整 spec，且实施 HTML 时都达到了 marketing-ready 质量。这证明方法论本身不依赖单一执行者的天赋——**只要 brief 给得清楚，多个独立执行者能产出一致的高质量结果**。

### 洞察 2 · 「视角」必须具体到「作品 + 年份」

每个 brief 里都列出具体作品对话：
- Anderson → *The French Dispatch* (2021) + *Moonrise Kingdom* (2012) + Penguin Classics dust jackets + 1960s Olivetti catalogues
- WKW → *In the Mood for Love* (2000) + *2046* (2004)
- Vignelli → 1972 NYC Subway map + Knoll identity manual + *The Vignelli Canon*
- Hara → MUJI brand 1995-2023 + 《白》 + Junya Ishigami transparency
- Kusama → Infinity Mirrored Rooms (2013-2023) + Polka Dot Obsession 装置

**实战结果**：所有 subagent 都准确捕捉到了该作品的核心 visual DNA，而不是流派的「平均值」。

### 洞察 3 · 反 AI slop 的「风格强化版本」是关键

通用 anti-slop（紫渐变 / emoji / SVG 人物）适用所有版本。但**每个风格还要写「专属 anti-slop」**：

- Bass: 不用 Helvetica（太干净，Bass 是粗犷）
- Vignelli: 不用圆角（所有 corner 90°）
- Hara: 不用任何渐变 + 不用 sans display
- Kusama: 不用现代 SaaS look
- Anderson: 不用 cyber 配色
- WKW: 不用 Inter（WKW 用衬线）

加了这些后，6 个版本风格纯度极高，无一相互趋同。

### 洞察 4 · 多视角的真正价值不是「选 winner」

最初设想是 A/B test 选最好的版本。实际审校时发现：**6 个版本各自有清晰 use case**：
- v5 基线 → 产品页 / 微信读书（信息密度高）
- Anderson → 公众号长文头图（翻杂志感强）
- WKW → B 站 / 中文文化向（怀旧温度）
- Vignelli → 设计圈 / Dribbble（每帧都是印刷海报）
- Hara → 客户演示 / 静态截图（极简哲学）
- Kusama → X 短视频 / 病毒传播（视觉冲击）

**结论**：marketing 不是 single-shot，是 platform-specific multiplex。6 视角实验的真正价值是**让一个项目有 6 个差异化武器**，不是让 5 个版本上不了台面。

### 洞察 5 · 单个视角中断的代价

6 个里 1 个中断（Bass 首轮 socket error）。处理代价：重做该视角（5 分钟简化版 brief + 约 12-15 分钟）。整体耗时以 6 个视角依次完成计，单个中断只增加该视角的重做时间。

### 洞察 6 · 视角之间的间隙必须做实质工作

每个视角完成需要约 12-15 分钟（历史记录）。这段时间主线程绝不该空闲：

- **修主版本 bug**（用户已经反馈的）
- **写 review framework**（等审校时填）
- **沉淀方法论到 skill**（如这份 case study）
- **准备 final summary**（用户回来一目了然）

这是多视角实验中「主线程职责」的记录——不是空等结果，是在视角之间持续推进。

---

## 何时启用「多视角实验」

| 场景 | 是否启用 | 原因 |
|------|---------|------|
| 用户明确说「想看不同方向」「再多做几个版本」 | ✅ 立刻启用 | 直接需求 |
| 第一版做出来用户不满意但说不清要啥 | ✅ 启用 | A/B 选优于「我猜你要啥」 |
| 项目准备多平台分发（X / 公众号 / B 站 / 朋友圈） | ✅ 启用 | 每平台一个版本 |
| 客户没拍板风格但有预算（time + token） | ✅ 启用 | 反复改 = 5 倍代价 |
| 用户已经给了明确风格参考且只要 1 个版本 | ❌ 不启用 | 浪费 |
| 任务是简单 motion graphic / icon 动画 | ❌ 不启用 | 过度工程化 |
| 时间紧 < 30 分钟 | ❌ 不启用 | 6 个视角依次产出跑不完 |

---

## 完整方法论流程图

```
用户 brief（含质量预期）
       ↓
[主线程] 写 v5 基线 director's notes（万字级 5 大部分）
       ↓
[主线程] 实施 v5 HTML + 截关键帧（marketing baseline）
       ↓
[决策点] 是否启用多视角？
       ↓ YES
[主线程] 选 6 个差异化视角 + 写 6 份独立 brief（每份 8 字段）
       ↓
[6 视角依次 inline]
   ├── v5a brief → director-notes + html + keyframes + README
   ├── v5b brief → ...
   ├── v5c brief → ...
   ├── v5d brief → ...
   ├── v5e brief → ...
   └── v5f brief → ...
       ↓
[主线程同步做] 修 v5 bug · 写 review framework · 沉淀方法论
       ↓
[全 6 通知到达]
       ↓
[主线程] 失败检测 + 重试 / 补截图
       ↓
[主线程] 5 维度评分 + 3 顶层问 + use case 分配
       ↓
[主线程] 写 final REVIEW.md
       ↓
[交付] 6 完整版本 + review + 平台分发推荐
```

---

## 相关文档

- 完整方法论：`references/launch-film-director-notes.md`
- 单视角样本（v5 基线）：未随本包发布
- 实战项目位置：作者本地 demos 目录（含 6 + 1 视角全套文件，未随仓库分发）
- 审校 review：作者本地 REVIEW.md（未随仓库分发）

---

*Last updated: 2026-05-11*
*Real case study: huashu-md-html v2.0 launch film 6-perspective parallel experiment*
