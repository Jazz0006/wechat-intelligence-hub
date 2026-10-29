# Windows 10/11 x64 使用与验收

本分支新增原生 PowerShell 安装、只读 Win32 获取模块、Hub 的 Python 直连入口。
**这不是微信全部 4.x 构建的兼容承诺。当前开发在 Mac 完成，尚无本分支 Windows 真机微信读取证据。**
Windows CI 定义了真实 Win32 自身内存、ACL、加密库和安装器检查；工作流尚未在本次会话执行，不能称为 Windows 已验收。

## 安装与已有材料

需要 Windows x64 的 Python 3.11 或 3.12、PowerShell、已同步本人聊天的微信。
在仓库根目录的 PowerShell 中运行：

```powershell
.\scripts\install.ps1
$access = Join-Path $env:LOCALAPPDATA 'RionWeChat\bin\rion-wechat-access.ps1'
$cli = Join-Path $env:LOCALAPPDATA 'RionWeChat\bin\rion-wechat-cli.ps1'
& $cli self-test --require-sqlcipher
```

可用 `-Python 'C:\Python312\python.exe'` 选择实际解释器，或 `-Prefix` 指定尚不存在的本机目录。
安装目录仅授予本人和 SYSTEM 访问；已有目录不覆盖。安装不会请求提权、修改 PATH、关闭系统防护、读取进程或获取材料。
脚本若被设备执行策略阻止，应由管理员按组织策略批准；本项目不修改机器执行策略。

已有本人材料时优先复用：

```powershell
$databaseRoot = 'D:\WeChat\xwechat_files\your-account\db_storage' # 改为本人账号
& $access diagnose --source 'D:\Private\access.json' --database-root $databaseRoot
& $access onboard --source 'D:\Private\access.json' --database-root $databaseRoot --apply
& $cli doctor
```

以上成功不代表手机全量历史已同步；必须检查 `live_database_read_ok`，并抽检已知消息。

## 缺少材料：独立确认的实验性获取

只允许用户主动选择的本人微信进程和单一账号目录。不自动选择多个账号或 PID。
先让微信保持正常登录并打开目标聊天；不要以管理员身份重新启动微信。

```powershell
Get-Process -Name Weixin,WeChat -ErrorAction SilentlyContinue | Select-Object Id,ProcessName
$wechatProcessId = 1234 # 从上一步选择实际主进程，不能照抄示例数字
$plan = Join-Path $env:LOCALAPPDATA 'RionWeChat\plans\first-access.json'
& $access windows-plan --pid $wechatProcessId --database-root $databaseRoot --out $plan
```

`windows-plan`不读取进程内存。它检查本人进程 SID、x64 架构、活动微信 DLL 4.x 文件版本、程序/DLL SHA256、进程创建时间，以及所选数据库页头。私有计划不应上传；15 分钟后过期，重启或升级微信、数据库变化后需要重新准备。

确认授权读取该进程后才运行：

```powershell
& $access windows-acquire --plan-file $plan --confirm-process-read --timeout 60 --max-mb 512 --max-candidates 256
```

读取仅使用 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`，不请求全部权限、不启用 SeDebugPrivilege、不注入、不写进程、不退出/重启微信。普通用户是否能读取仍由进程访问控制与设备策略决定；拒绝访问即停止，不自动提权。
外层只终止自己创建的扫描子进程；同时限制时间、尝试读取的字节数和候选数。同一计划只能尝试一次；失败后先审查结果，不循环重试。

### 候选规则与版本边界

默认仅识别内存中的 SQLCipher `x'raw-key'` / `x'raw-key+salt'` 字面量。
当前没有内置、经过微信真机验证的 4.1.x 内存布局。未找到此类字面量时可能返回 `no_verified_keys`；这不是权限或微信版本不兼容的证明。

特定构建需要其他布局时，可由维护者审阅完整来源与转换算法后提供 `--profile`：

```json
{
  "schema_version": 1,
  "dll_version": "4.0.0.0",
  "dll_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "rules": [{"pattern_hex": "544553544f4e4c59", "offset": 8, "length": 32,
             "encoding": "binary", "mode": "raw_key"}]
}
```

**上面完全是虚构格式示例，不可用于真实微信。** `pattern_hex`为8–128字节签名，`offset`为相对签名位置的有符号偏移，`length`为读取的编码字节数（32/64）；`encoding`支持binary/hex，`mode`支持raw_key/password，可选`xor_hex`仅执行一次重复XOR。password模式按每个数据库salt做SQLCipher 4派生；禁止把其他provider已经转换完成的候选再次XOR。
profile必须匹配当前实际加载 DLL 的完整版本与哈希，并在获取时另加 `--confirm-reviewed-profile`。profile可能包含敏感辅助值，计划和材料均须留在本机。

## 验证、接入与导出

候选必须先通过真实页头 HMAC，再经独立 SQLCipher 读取数据库结构，才保存在私有目录。
结果只返回固定状态、计数和材料路径，不返回候选、密钥或内存。`material_verified`只表示材料验证通过，尚未发布 Reader 配置；`partial_key_coverage`只表示部分库可读。
获取器不覆盖或修改已有配置、Profile、原始数据库和既有材料。

```powershell
# 将上一命令返回的 material_file 填入下面；不需要打开文件或复制key
& $access onboard --source 'C:\Private\verified-candidates.json' --database-root $databaseRoot --apply
& $cli doctor
$since = (Get-Date).AddHours(-24).ToString('o')
$until = (Get-Date).ToString('o')
& $cli resolve-chat '目标联系人'
& $cli export '上一步确认的唯一会话ID' --after $since --before $until --format markdown --limit 1000 --path "$env:LOCALAPPDATA\RionWeChat\exports\chat.md"
```

导出超过1000条时要继续分页，并检查消息数量、起止时间、收发方向和已知文本。
图片/语音/视频的解密不在此获取模块保证范围内。

Hub 可从仓库源码运行，默认会直连安装的 Python Reader；不会把聊天名或关键词交给 cmd.exe：

```powershell
$python = Join-Path $env:LOCALAPPDATA 'RionWeChat\share\rion-wechat-cli\venv\Scripts\python.exe'
& $python .\projects\wechat-intelligence-hub\wechat_intelligence_hub.py chat-history '目标联系人' --limit 100
```

自定义安装目录可通过 `WECHAT_READER_BIN` 指向对应的 `rion_wechat_reader.py`。HTML 报告仍需要 Hub 文档列出的额外依赖，Markdown 导出不需要。

## 必须在 Windows 真机补齐的验收

- 原生安装与PowerShell 5.1/7调用；Windows ACL和Win32自身测试。
- 本人微信完整构建、活动 DLL 版本/哈希、PID归属；原生模块真实候选命中率。
- 逐库 SQLCipher 验证、doctor、已知私聊/群聊文本、最近24小时导出与分页。
- 普通用户访问被拒绝、微信重启/升级、计划过期、扫描超时、部分覆盖与旧配置保留。

本机测试和虚构数据库不能代替以上真实微信验收。

Win32依据：[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)、[VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)、[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)。
