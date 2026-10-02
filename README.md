# achievement_unlocker —— 运行时成就解锁 + 铁人控制台解锁 DLL

配合 `stellaris_mod_injector` 使用：把编译好的 `achievement_unlocker.dll` 放进游戏根目录的
`injected_mods\`，注入器会自动把它注入 `stellaris.exe`。**不修改任何游戏文件**，所有改动
只在进程内存里，重启游戏即消失。

它解决六件事：前四件对应反编译 `stellaris_4.5_source.cpp` 里成就判定的四个字节，
后两件解除铁人模式下的控制台封锁：

| # | 补丁 | 运行期签名（名字 = 日志里的名字） | 改动 | 作用 |
|---|------|--------------------------------------|------|------|
| 1 | mods / 文件校验和 (`mods / file checksum`) | `8B F0 85 C0 41 0F 94 C6` | `85 C0` → `31 C0` | 游戏文件校验和不符时也不禁用成就 |
| 2 | 控制台 → 存档标记 | `C6 80 FC 00 00 00 01 E8` | `01` → `00` | 执行过控制台命令不再写"作弊"到当前存档 |
| 3 | 控制台 → 管理器标记 | `C6 80 83 00 00 00 01` | `01` → `00` | 同上（成就管理器的 0x83） |
| 4 | 读档 → 管理器标记 | `0F B6 8E FC 00 00 00 88 88 83 00 00 00` | 6 字节 → `90`×6 | 加载旧"作弊"存档不再同步禁用标志 |
| 5 | 铁人控制台 (`ironman console (idle)`) | 见下 | `01` → `00` | 铁人模式下也能打开控制台并执行命令 |
| 6 | 铁人控制台 (`ironman console (restore)`) | 见下 | `01` → `00` | 同上（第二处，`CGameIdler::RestoreDeviceObjects`） |

补丁 5 的签名：

```
45 38 BE 80 01 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00
44 38 B9 1E 01 00 00 75 ?? 40 32 FF EB ?? 40 B7 01
```

补丁 6 的签名：

```
80 BE 80 01 00 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00
80 B9 1E 01 00 00 00 75 ?? 32 DB EB ?? B3 01
```

（注：使用deepseek-v4.1-flash编写，harness为Kimi Code）

### 铁人控制台补丁（5/6）的原理

游戏每帧从铁人标志 `[[CGameState]+0x9B0]+0x11E` 推出一个"控制台禁用位"（`联机 || 铁人`），
然后做两件事：写进 `CConsoleCmdManager+0xA9`（`CConsoleCmdManager::Execute` 会据此拒绝
**所有**控制台命令），以及置位 `CConsole` 的 stay-hidden 闩锁（`CConsole::Show()` 见它直接
返回，所以连窗口都打不开）。这就是 `~` 在铁人档里毫无反应的原因。

补丁 5/6 只改这两处派生的**立即数**（`mov dil,1` / `mov bl,1` → `mov reg,0`，各 1 字节），
于是禁用位恒为 0：控制台能开、命令能执行。选择改这里而不是 `Execute` 里的判断，是因为
`Execute` 只管"执行"，界面还有一道 stay-hidden 闸；改派生值一次解决两道闸。

**`is_ironman` 触发器不做任何修改**：脚本里 `is_ironman = yes/no` 仍返回真实值，
存档、成就相关判定也不受影响。

副作用：禁用位与"联机禁用"共用，所以联机时的全局控制台封锁同样被解除；但联机侧并未完全
放开——一部分命令自己还会单独检查联机标志（反编译 3814468 / 3815026 / 3815792），
联机下还有 `CInGameIdler::ForceHideConsole`（707200）会再次隐藏控制台。

另外，DLL 会解析 `CAchievementsManager::AccessInstance()`：先取 1 号补丁点后面的 `call`，
失败再取 3 号补丁前的 `call`；同时用通配签名独立定位一次静态槽。**只有两条派生结果一致时才
采用**（只算出一条时，它必须与签名形状逐字节一致才采用），不一致或形状不符就拒绝——只打印
日志，不进监视循环（把标志写进无关对象是这里最不能接受的失败方式，宁可不用）。槽位确定后，
每 200 ms 强制维持标志 `80=0, 81=1, 82=1, 83=0, 84=0`；每次写入前还会确认目标对象"看起来
仍是管理器"（vtable 落在镜像内、`0x81`–`0x84` 是 0/1），否则拒绝写并在日志里说明。这一步是
跨版本兜底：

- 注入时机晚于初始化（例如附加到已运行的游戏）时，标志已经变成"禁用"，靠它扳回来；
- 某个版本改了代码形状、签名找不到时，剩下的补丁点仍生效，日志会逐条说明；
- 槽位解析不出来、或解出来的对象不像管理器时，只打印日志，一个字节都不写。

## 判定链背景（简版）

`CAchievementsManager`（反编译 1.71M 行附近）的 6 个字节：

- `0x81` savegame_ok、`0x82` game_ok（文件校验和）、`0x83` 存档用过作弊、`0x84` 调试成就、
  `0x85` 后端未就绪、`0x80` 死条件（无写入者）。
- `IsAchievementsOk` = `!0x84 && 0x81 && 0x82 && !0x83`；`Update` / `OnGameStart` 用同一组
  条件解锁成就（`0x84` 置位时只模拟、不解锁）。

## 关于"游戏文件校验和"校验了哪些文件

4.5 的 data 校验和由游戏根目录的 `checksum_manifest.txt` 清单驱动：
`CApplication::CalculateGameFilesChecksum` → `CChecksum::SetupFromManifestFile` →
`CreateFileList`（用 `VFSEnumerateFiles` 枚举，所以 mod 覆盖/新增进这些虚拟目录的文件也会被算）
→ 对每个文件 `MD5(文件内容 + 文件路径)`，再混入版本名字符串。

4.5.1 的清单内容（逐条）：`common/`（递归，`.txt` / `.shader` / `.csv`）、
`events/`（递归，`.txt`）、`map/`（递归，`.shader` / `.txt`）。
`gfx/ interface/ localisation/ sound/ music/ fonts/ dlc/` 等不在清单里；exe 本体有单独的
校验和（只出现在版本号显示里），成就判定只比较 **data 校验和**。

## 构建

```
cd achievement_unlocker_src
build.bat            :: 需要 MinGW-w64 的 g++；不在 PATH 时先 set MINGW_BIN=...
```

产物在 `build\achievement_unlocker.dll`，发布用的副本放在 `..\achievement_unlocker_dll\`。

## 离线验证（不需要启动游戏）

```
cd tools
build_test.bat
build_test\scan_test.exe <path-to-stellaris.exe>
```

`scan_test` 把 exe 按加载布局映射到内存，然后直接调用 DLL 里同一份扫描/补丁代码，跑三遍：
dry-run → 写补丁 → 再扫描（幂等检查）。报告里除了补丁 RVA，还会打印槽位是怎么定下来的
（`call site + signature agree` 等），一眼就能看出新增的交叉校验是否生效。两个真实构建
（4.5.0 / 4.5.1）的输出与预期值（补丁字节 RVA 依次为
`0x1B94A0 / 0x9225ED(5.1: 0x92290D) / 0x9225F9(5.1: 0x922919) / 0x24A9CC`，
两个铁人控制台点 `0x3329B7 / 0x333D8D`——**两个构建完全相同**，
AccessInstance RVA `0x5AE7F0 / 0x5AE8A0`，槽位 RVA `0x3153E78 / 0x3154E70`）完全一致，
见 `..\achievement_unlocker_dll\验证记录_离线扫描.txt`。

## 本次修订（r3，2026-10-02）

**新增两个补丁点，功能是"铁人模式下也能用控制台"**；原来的四个成就补丁一字未改，
`is_ironman` 触发器**不做修改**。

- 动机与定位：`CGameIdler::Idle` / `CGameIdler::RestoreDeviceObjects` 每帧把
  `联机 || 铁人` 写进控制台的禁用位（`CConsoleCmdManager+0xA9`）并置位 stay-hidden 闩锁；
  `CConsoleCmdManager::Execute`（反编译 7946279）与 `CConsole::Show()`（7907204）据此分别
  拒绝命令与窗口。补丁 5/6 把这两处 `mov reg,1` 的立即数改成 0（各 1 字节），一次解决
  "命令执行"和"窗口被隐藏"两道闸。
- 为什么不改 `Execute` 里的两处条件跳转：那样只放开命令执行，界面仍被 stay-hidden 挡住；
  而 stay-hidden 是每帧重建的，"定时器写内存"式的兜底在这里不成立。
- 安全性：补丁 6 所在函数里，被改的寄存器（`bl`）在写入后即死，没有别的用途（反汇编确认）；
  补丁 5 的寄存器本来就只用于这两件事。
- 跨版本：两条签名在 4.5.0（`D:\zStudy\stellaris\stellaris_4.5.exe`）与 4.5.1（Steam 版）
  上**都只命中一次，且 RVA 相同**（补丁字节 `0x3329B7 / 0x333D8D`）；"已打过补丁"的形态在
  两个构建里都不出现，幂等判定干净。离线验证输出见
  `..\achievement_unlocker_dll\验证记录_离线扫描.txt`。
- 副作用：禁用位与"联机禁用"共用，联机下的全局封锁同样被解除；但单个命令若自己检查联机
  标志（3814468 / 3815026 / 3815792）仍会被拦住。
- 构建标记更新为 `r3 2026-10-02`（写在日志第一行）。

## 本次修订（r2，2026-09-29）

代码审查后的加固：补丁字节与整体行为不变，修的是"出错时会怎样"。

1. **槽位解析加了交叉校验**：签名派生不再只是"两条 `call` 都失败时的兜底"，而是每次都算，
   与 `call` 派生的结果比对；不一致或形状不符就拒绝进监视循环（日志里会写出来源与两条 RVA）。
   之前只有在 `access_instance` 完全拿不到时才会走签名，文档里承诺的第三条路径实际上是死路。
2. **所有解引用都先做区间校验**：`call` 目标、`FindMovRaxRip` 的 0x20 字节读取窗口、槽位，
   都要求落在镜像内；之前 `call` 目标不检查就直接解引用。
3. **监视循环加了"这还是管理器吗"自检**：vtable 在镜像内 **且** `0x81`–`0x84` 恰好是 0/1
   才写；否则打印一次说明后不再碰它。
4. **3 号点的幂等模式改自足**：`after` 从 10 字节缩到 7 字节，不再钉住被补丁指令之后那条
   指令的字节（那条指令一变，就会把"已打过补丁"误报成"找不到"）。
5. **补丁写入改成单次 8 字节存储**：6 字节的读档补丁原来会被编译成 4+2 两条存储，中间态
   （`90 90 90 90 00 00`）会解码成一条往 `[rax]` 写内存的指令；现在读取整个 8 字节窗口、
   合并后一次写出（对齐窗口时架构保证原子，非对齐但同缓存行在 P6 之后实际上也不会撕裂），
   窗口内与补丁相邻的字节原样写回。
6. **签名解析不再静默截断**：`ParseSig` 遇到非法记号返回空，`ApplyAll` 会把这种点报成
   `bad patch spec`，不会在缩短后的模式上乱写。
7. **日志路径与时间戳**：模块路径用 1024 缓冲并检测截断（截断就退回相对路径，避免整个日志
   消失），日志第二行写明实际路径；`g_start` 改成原子变量；`r.ok` 与 `LogPath()` 不再是死代码。
8. **离线工具的 PE 解析加了边界校验**：畸形/截断的输入不再越界读，`SizeOfHeaders` 也按
   `SizeOfImage` 夹紧（原来是潜在的越界写）。

加固后重跑了 4.5.0 / 4.5.1 两个构建的离线验证（《验证记录_离线扫描.txt》已按新输出重新生成，
补丁 RVA 与加固前完全一致），另做了两组台架测试：`WriteBytes` 在 1–16 字节、所有对齐下
只改目标字节、邻居不变；人为破坏调用点/签名之后，槽位解析按预期拒绝或回退到签名。

## 目录

```
achievement_unlocker_src/
├── build.bat              MinGW-w64 构建脚本
├── README.md              本文件
├── src/
│   ├── dllmain.cpp        DllMain → 工作线程
│   ├── unlocker.h/.cpp    六个补丁点 + 标志保持循环
│   ├── scan.h/.cpp        模式扫描 / 内存写入 / 主模块信息
│   └── log.h/.cpp         写 achievement_unlocker.log
└── tools/
    ├── scan_test.cpp      离线验证工具（映射 exe 后跑真实代码）
    └── build_test.bat

achievement_unlocker_dll/
├── achievement_unlocker.dll
├── achievement_unlocker.dll.bak_before_console_unlock  r2（加铁人控制台补丁前，回退用）
├── achievement_unlocker.dll.bak_before_hardening       r1（加固前，更早的回退点）
├── check_save.py                                   存档自检工具（验证用，见使用说明）
├── 使用说明.md
└── 验证记录_离线扫描.txt
```
