# macOS 接入候选补丁

这是用于兼容验证的可选源码补丁，**不是默认获取工具，不随 Skill 安装执行，不包含二进制或任何 key**。已有 Reader 配置可用时继续复用，不重新获取。

## 针对的问题

- 固定上游为 `01e96fa58ce3ff061dce83e4c36f62104ebc6b16`，包含上游新合入的 [Intel PBKDF 参数修复](https://github.com/r266-tech/wxkey/commit/f0978ce)。旧基线仅按 ARM 寄存器读取参数；这项修复不是所有 Mac 问题的统一答案。
- LLDB 启动显式设置用户、用户组和 HOME；在程序入口暂停后核验真实/有效 UID、GID。身份不符或无法确认就终止该目标，不继续捕获。
- 使用异步 LLDB 和有截止时间的事件等待，避免同步 Continue 卡住循环；同一次暂停不重复处理。外层接入助手仍负责总超时。
- 已知命令失败先执行 defer 清理再退出；副本准备/启动失败也尝试重开原微信，open 以原用户身份执行。清理副本按应用路径重新识别进程，不直接使用早先保存的 PID。
- `original_reopen_requested` 仅表示已请求打开，**不表示恢复登录成功**。终止信号、系统阻止启动等情况仍可能需要人工恢复，不能保证任何失败都能自动恢复。

补丁未改动密钥验证算法；导入仍需 Reader 验证真实数据库。它也没有解决 Windows 获取、所有微信版本兼容、系统启动策略或手机未同步历史。

## 固定构建流程

以下命令由 Codex 在普通用户权限执行。先审核来源与补丁，再准备源码；不要运行上游安装脚本或用 `@latest`。示例目录需要是尚不存在的新目录，已有目录不要覆盖。

```bash
git clone --no-checkout https://github.com/r266-tech/wxkey.git /tmp/wxkey-upstream-review
python3 providers/wxkey/prepare_candidate.py \
  --source /tmp/wxkey-upstream-review --out /tmp/wxkey-reviewed-candidate

cd /tmp/wxkey-reviewed-candidate/source
GOTOOLCHAIN=local go test ./cmd/wxkey \
  -run 'Test(FailureUnwindsCleanup|SuccessfulCommandReturnsZero|UnexpectedPanicNotHidden|LaunchCandidateIsolated|PBKDF)' -count=1
GOTOOLCHAIN=local go build -trimpath -o ../wxkey ./cmd/wxkey
go version -m ../wxkey
shasum -a 256 ../wxkey
```

需要 Go 1.26.5。准备脚本仅归档固定提交、校验补丁摘要、应用补丁并写源码收据；不联网、不编译、不运行、不安装获取工具。原 checkout 即使有本地改动也不会被修改，归档只取固定提交。构建会按 go.mod/go.sum 获取依赖，不能把准备收据当成构建或获取成功证明。

可选真实 LLDB 小程序测试，在仓库根目录运行：

```bash
/usr/bin/python3 providers/wxkey/check_lldb_fixture.py \
  --source /tmp/wxkey-reviewed-candidate/source
```

它只编译并调试自己创建的临时程序，不访问微信，不读取进程密钥，不提权。运行前仍应审核源码。

获取不是上述准备流程的一部分。确需首次获取时，先由 `access.sh plan` 锁定已审核二进制的 SHA256，再按[独立授权流程](../../skills/wechat-cli/references/experimental-access.md)说明微信可能退出、重启和副本重签名的影响。用户明确确认后才能执行；不得直接单独运行此工具的 bootstrap 来跳过接入助手边界。

## 验证状态

- Python 16 项无微信测试：12 项启动/身份/截止时间测试及上游 4 项 ARM/Intel 参数测试。
- Go 针对性回归通过，覆盖退出时清理、意外 panic 不被吞掉及现有 PBKDF 诊断。
- 2026-09-14，macOS 26.5.1 ARM64 的普通用户 LLDB 临时程序测试通过；1.5 秒截止时间的实际返回约 2 秒，受单次 1 秒事件等待影响。
- **未验证**：root 到普通用户的真实 LLDB 启动、任何新微信账号首次取得 key、Intel 实机、macOS 27 实机，以及上述版本上的失败后 GUI 登录恢复。

因此保持 `candidate_not_default`。下一步是由知情且明确授权的使用者在兼容测试机器上逐阶段验收，不能拿当前正常使用的账号反复退出登录来凑成功率。

## 依据与许可

- [用户报告 Issue #3](https://github.com/Rion-Wu-tech/wechat-intelligence-hub/issues/3)：问题线索，不等于维护者已在该机器复现。
- [LLDB SBLaunchInfo](https://lldb.llvm.org/python_api/lldb.SBLaunchInfo.html)、[SBProcessInfo](https://lldb.llvm.org/python_api/lldb.SBProcessInfo.html)、[SBListener](https://lldb.llvm.org/python_api/lldb.SBListener.html)：启动身份、实际身份和事件等待接口。
- 上游版权与 MIT 许可保留在 [LICENSE.upstream](LICENSE.upstream)。
