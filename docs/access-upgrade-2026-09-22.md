# 接入兼容与诊断升级（2026-09-22）

本轮优先修复已有材料导入、误判和诊断。首次获取仍受系统、微信构建、provider及登录状态影响；尚不能承诺所有版本一键成功。

## 本轮修复

- 搜索发送者、收发方向、消息类型的过滤移到分页之前；`has_more`通过多取一条判断，避免提前终止或漏页。
- 搜索摘要/不含正文模式移除底层原始正文和压缩字段，避免精简输出仍夹带完整数据。
- JSON支持UTF-8、UTF-8 BOM、UTF-16和UTF-32，兼容Windows导出的文件。编码错误不回显内容。
- 导入接受`raw_key`字段及严格的SQLCipher `x'…'`字面量；顶层目录/版本元数据不会再当成数据库密钥。
- schema-2和Reader salt映射都支持96位raw key+salt，必须核对后32位；冲突字段、口令、越界路径仍拒绝。
- 解密成功计数与表结构识别分开。可以打开但尚不支持的库计入`unrecognized_readable_count`，不误报为key无效。
- 验证结果标明`verification_level=sqlite_schema_read`、扫描截断和错误计数；这不是全页完整性验证或手机全量覆盖证明。
- 材料失败保留固定错误码及下一步，不再一律返回笼统的validation_failed。
- 新增`diagnose`：可预览指定材料，使用临时配置，不覆盖现有安装，也不启动获取。
- 同日后续：连接和验证临时目录改用Windows ACL，修复残留Unix模式位判断；已有目录不自动改权限。新增`diagnose --support-summary`白名单反馈输出和Windows原生CI虚构数据库检查，见[接入支持流程](access-support.md)。助手revision为2026-09-22.2。

## 给Codex的提示词

> 帮我诊断本机微信接入。先运行wechat-cli的access.sh diagnose，核对实际运行环境、系统、微信完整版本、失败阶段和数据库覆盖。有材料时用diagnose --source及本人数据库目录临时验证，不让我复制key。按具体错误修复依赖、编码、格式、目录或权限；不要根据“找不到key”直接让我降级或重新获取。最后用doctor和已知群聊/私聊文本确认。若仍卡在首次获取，请明确缺少哪个平台的真机验收。

macOS已安装Skill：

```bash
bash ~/.codex/skills/wechat-cli/scripts/access.sh diagnose
bash ~/.codex/skills/wechat-cli/scripts/access.sh diagnose \
  --source /path/to/private-access.json --database-root /path/to/account/db_storage
```

Windows已有Python运行环境可直接调用同一Python助手，无需Bash：

```powershell
& '<Reader环境的python.exe>' 'projects/rion-wechat-reader/rion_wechat_access.py' diagnose
```

诊断返回码0只表示诊断完成。检查`state`、`live_database_read_ok`和可选的`material_preview`。如果主配置可读、指定材料失败，两者分别保留，不覆盖主配置。

## JEV的用途

JEV可以辅助把匿名阶段信息分到依赖、权限、材料、账号或provider。它不能验证密钥、读取内存或替代SQLCipher。

`diagnose --jev-request`仅生成白名单请求对象：固定状态码、系统类别、历史信号和恢复标记；没有聊天、联系人、文件路径、数据库内容或密钥，也不会联网。只有显式调用外部API才发送这个请求对象，不能把整份原日志或私聊提交给模型。API不可用时本地诊断照常使用。

`projects/rion-wechat-reader/examples/jev-access-triage.json`是三条全虚构验收案例。预测只是建议，不允许据此自动启动获取、放宽权限或删除恢复锁。官方接口：[TypeSafe API](https://docs.typesafe.ai/api)。

## 调研后采用与暂不采用

| 来源 | 可借鉴内容 | 适用边界 |
| --- | --- | --- |
| [SQLCipher官方API](https://www.zetetic.net/sqlcipher/sqlcipher-api/) | raw key、salt与口令的区别；本机验证 | 模型预测不能代替实际读取 |
| [sqlcipher3 0.6.2](https://pypi.org/project/sqlcipher3/0.6.2/) | 已提供Windows x64/ARM64等wheel，优先匹配Python ABI | wheel存在不代表该机器DLL加载及真实读取已验收 |
| [Windows社区分支](https://github.com/iversonzhang50-gif/wechat-intelligence-hub-windows) | 原生安装、固定依赖、ACL、中文路径、自检 | 接入文档仍不捆绑获取工具，非一键取key |
| [WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) | V4分阶段转换、逐库验证和文本解码 | 社区特定构建成功；当前GitHub许可元数据为null，未复制源码 |
| [wxkey v1.4.8](https://github.com/r266-tech/wxkey/releases/tag/v1.4.8) | macOS阶段计数、账号salt匹配与失败清理 | 本仓库Issue #2/#3显示不同系统失败，不能泛化支持 |
| [chatlog #264](https://github.com/sjzar/chatlog/issues/264) | 同一no valid key found在特定版本出现 | 旧教程的版本、关闭SIP或反复重试建议不作为默认方案 |

检索涵盖项目源码、官方文档、发布信息、问题单和教程；具体实现以原始源码、官方API及本地复现为依据。没有可靠原始证据的文章或视频不列为有效修复。

## 发布及真机验收

本轮本地发布检查通过：Hub源码135项、打包后的Hub135项、Reader/接入145项（其中2项原生Windows测试在Mac跳过）、provider补丁3项，另含临时安装、能力契约和私有标识扫描。共418次执行，416项通过、2项明确跳过；不是418台设备。Windows原生CI另行检查实际ACL及虚构加密库，不能证明真实微信首次获取成功。

同日[Windows原生CI](https://github.com/Rion-Wu-tech/wechat-intelligence-hub/actions/runs/35638032153)已通过：Python 3.11、3.12两组均完成实际ACL、中文路径和UTF-16材料解密测试。使用虚构数据库，没有安装或访问微信，没有验证首次获取。

维护者Mac升级后`diagnose`为`ready`，并成功读取已知私聊。诊断没有联网、改写配置或重新获取材料。JEV三条虚构案例返回预期分类，仅证明本次连通及样例通过。

本次测试能证明：格式兼容、错误分类、搜索分页以及虚构加密数据库读取。维护者现有Mac可读只能证明读取回归，不能计入新用户首次获取成功率。

仍需Windows与Mac失败设备各完成一次：环境诊断→本人材料获取/复用→逐库验证→doctor→已知消息→Hub报告。记录完整系统/微信构建、provider固定提交、耗时、覆盖数和失败阶段；只保存匿名计数。未完成前不宣传“最新版全部支持”。

发布前审核完整差异、跑发布检查、排除私有反馈报告。不得把私聊附件或本机key一起推送；历史报告需重新渲染才应用HTML安全修复。
