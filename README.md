# NEU Network Auto Login

面向东北大学校园网的自动登录工具。  
目标很直接：让你开机后少点几次网页登录，网络断开后尽快恢复在线。

如果这个项目对你有帮助，欢迎在 GitHub 点一个 Star：
`https://github.com/zhangfunning/neu-autologin`

## 这个软件能做什么

- 自动检测网络状态，离线时触发校园网登录
- 支持手动一键登录、手动一键注销
- 支持最小化到系统托盘，后台运行
- 支持开机启动，进入系统后自动监控
- 记录运行日志，方便排查登录失败原因
- 本地凭据使用 DPAPI 加密保存（按当前 Windows 用户隔离）

## 适合哪些同学

- 宿舍、实验室经常掉线，需要频繁重新认证
- 不想每次都手动打开门户页面登录
- 想要一个可追踪、可调试、可二次开发的校园网工具

## 项目结构

- `NEUNetworkAutoLogin.Wpf/`：WPF 源码
- `build-gui-exe.ps1`：打包脚本
- `NEUNetworkAutoLogin.exe`：当前生成的可执行文件
- 认证链路：当前版本已改为纯 `HttpClient`，不再依赖 Node/Playwright 脚本

## 运行

```powershell
cd .\autologin
.\NEUNetworkAutoLogin.exe
```

## 重新打包

默认打包（自包含，目标机器无需额外安装 .NET 运行时）：

```powershell
cd .\autologin
powershell -ExecutionPolicy Bypass -File .\build-gui-exe.ps1
```

小体积打包（目标机器需已安装 .NET 桌面运行时）：

```powershell
powershell -ExecutionPolicy Bypass -File .\build-gui-exe.ps1 -DeploymentMode FrameworkDependent
```

## 数据目录

程序运行数据位于：

```text
%LocalAppData%\NEUNetworkAutoLogin
```

- `settings.json`
- `credential.dpapi`
- `logs\autologin-YYYY-MM-DD.log`

## 给 NEU 同学的话

这个项目会长期按真实抓包链路维护登录与注销流程。  
如果你在不同校区、不同网络环境下测试过，欢迎提 Issue 反馈结果，一起把它做成东北大学同学都能稳定用的工具。
