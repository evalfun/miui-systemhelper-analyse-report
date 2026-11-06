# SystemHelper 逆向分析报告

> **分析对象**：`SystemHelper.apk` 及 `oat/arm64/SystemHelper.odex`、`SystemHelper.vdex`  
> **报告日期**：2026-11-06  
> **样本版本**：`1.2-20220907`（versionCode 3，2022 年构建的历史版本）  
> **分析方式**：纯静态逆向分析；未向真实服务器发送任何请求，未进行动态调试或漏洞利用。  
> **一句话结论**：`SystemHelper` 是中国联通预置的**终端管理/终端注册组件（DM agent）**，不是反诈 App，也不是远控木马。它按开机、换卡、定时、周任务等事件，采集设备标识、SIM 标识、蜂窝小区、网络制式/VoLTE/5G 状态、已用 App 的时长和流量等，加密后通过**明文 HTTP** 上报到联通 DM 平台 `dm.wo.com.cn:18080/registerv3`；失败会落库，下次作为 `History` 补传。默认每日一次基础注册、每 7 天一次 App 使用统计。

---

## 0. 版本时效性声明（重要）

> **本报告分析的是 2022 年就已出现/预置的 `1.2-20220907` 历史版本，不是 2024–2026 年的当前最新版本。**
>
> - 版本名 `1.2-20220907` 中的日期表明该 APK 构建于 **2022-09-07**；`versionCode` 仅为 `3`，属于较早期的预置组件。
> - 它只能代表当年预置在部分国行机型 `/product/priv-app/SystemHelper/` 下的旧版行为。
> - **当前最新版本可能已经发生变化**，包括但不限于：包名/证书、上报域名与协议、加密方式、采集字段、定时周期、厂商适配范围、权限申请、同意逻辑、组件导出属性、安全修复等。
> - 因此，本报告中的 URL、字段、默认间隔、行为描述和漏洞结论**只对该历史样本负责**；不要直接把本报告的结论套用到当前最新版本。
> - 如果要判断某台设备当前安装的版本，应以该设备实际 APK/oat 的**版本名、SHA-256、签名证书和反编译代码**为准，而不是以本报告为准。
> - 本报告提到“当前”“最新”时，均指**分析时的公开环境**；对样本本身的行为描述，均限定在 `1.2-20220907`。

---

## 目录

0. [版本时效性声明（重要）](#0-版本时效性声明重要)
1. [摘要](#1-摘要)
2. [样本信息与完整性](#2-样本信息与完整性)
3. [分析方法与工具](#3-分析方法与工具)
4. [应用身份与来源](#4-应用身份与来源)
5. [Manifest、组件与权限](#5-manifest组件与权限)
6. [运行机制与触发链](#6-运行机制与触发链)
7. [数据采集范围](#7-数据采集范围)
8. [上报协议与密码学](#8-上报协议与密码学)
9. [多厂商适配](#9-多厂商适配)
10. [同意机制与隐私问题](#10-同意机制与隐私问题)
11. [安全攻击面](#11-安全攻击面)
12. [它不是什么](#12-它不是什么)
13. [用途推断](#13-用途推断)
14. [与公开报道及当前版本的差异](#14-与公开报道及当前版本的差异)
15. [IOC 汇总](#15-ioc-汇总)
16. [处置建议](#16-处置建议)
17. [复现命令与证据索引](#17-复现命令与证据索引)
18. [结论](#18-结论)

---

## 1. 摘要

### 1.1 核心判断

| 判断 | 置信度 | 依据 |
|---|---|---|
| 这是中国联通相关的预置终端管理/注册组件 | 高 | 包名、`dm.wo.com.cn`、证书 `O=CU/OU=RI/CN=NewDM`、`pub.cer` 的 `O=UNICOM` |
| 它会把设备/SIM/蜂窝位置/App 使用数据上报到联通 DM 平台 | 确认 | `RegisterThread`、`DeviceInfo`、`QueryAppInfoThread`、`HttpEncryptHelper` |
| 它默认每日基础注册、每 7 天 App 统计 | 确认 | `GlobalSetting.DEFAULT_SCHEDULE_INTERVAL=86400000`、`DEFAULT_APP_INFO_INTERVAL=604800000` |
| 它是 `/product/priv-app` 下的特权系统应用 | 确认 | odex 字符串中的原始路径、`READ_PRIVILEGED_PHONE_STATE` |
| 它的同意检查偏弱且各品牌不一致 | 高 | 多数品牌只检查 `device_provisioned`；部分完全不检查 |
| 它不是反诈 App、不是录屏/远控木马 | 高 | 无相关权限、无录屏/无障碍/通知监听/远控代码 |
| 服务端具体用途 | 未确认 | 客户端只能证明采集与上报，无法证明服务端如何使用 |

### 1.2 关键行为速览

```text
首次开机/后续开机/每日定时/换卡/每周任务
        ↓
按机型选择 DeviceInfoReader（58 个）
        ↓
读取 IMEI/IMSI/ICCID/MSISDN/MNC/CellID/LAC/网络制式/VoLTE/5G
        ↓
RegType=A 时额外读取最近 7 天 App 使用时长和流量
        ↓
JSON → AES-128-ECB(key=MD5(json))
        ↓
RSA-1024(pub.cer) 加密 MD5，作为 sign 查询参数
        ↓
HTTP POST http://dm.wo.com.cn:18080/registerv3
        ↓
200/416 视为成功，清空 history；失败写入 SQLite，下次补传
```

---

## 2. 样本信息与完整性

### 2.1 文件信息

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `SystemHelper.apk` | 1,685,429 B | `416d0fc0405fc19b243e72f2a7963517e5b88991a7dfac494934449969a6015d` |
| `oat/arm64/SystemHelper.odex` | 29,672 B | `5f631f06231624d9e947b459a17351a35e80ac843e675235b05fd94eb479110f` |
| `oat/arm64/SystemHelper.vdex` | 2,559,004 B | `ac28e45a0877e1f5737f1dca702a19d5d0462a0ad688bdbaf1c03e6f0ecfd852` |
| `classes.dex`（APK 内） | 2,662,204 B | `508f4ffefd9d2dbf7ff12f7617ab5a05baecdede86952d411f1efdcc1ac068ef` |
| `AndroidManifest.xml`（二进制） | 7,972 B | `90cd7e086010b5ac3c963f6054dc7b4d45e455fc24ebd85e6409370edd5dbf25` |
| `resources.arsc` | 255,208 B | `37eb8c235d7e1239f0b367f04784a68045fa2a2bf3c3639fcb04792b74e92bcf` |
| `assets/pub.cer` | 596 B | `810c0122ba6af7a4b6a5921fdbbbf9197fb2e0b2e82de0c5aa40d28f1b7c6501` |

### 2.2 应用元数据

| 项目 | 值 |
|---|---|
| 包名 | `com.mobiletools.systemhelper` |
| 应用名 | `SystemHelper` |
| 版本名 | `1.2-20220907` |
| 构建时间（推断） | `2022-09-07`（从版本名中的日期推断） |
| 版本性质 | **2022 年历史版本，非 2024–2026 当前最新版** |
| versionCode | `3` |
| minSdkVersion | `24`（Android 7.0） |
| targetSdkVersion | `33`（Android 13） |
| `sharedUserId` | `com.mobiletools.systemhelper.uid` |
| `allowBackup` | `false` |
| `usesCleartextTraffic` | `true` |
| `appComponentFactory` | `android.support.v4.app.CoreComponentFactory` |
| 主 Activity | 无 `MAIN/LAUNCHER` |
| 唯一 Activity | `com.mobiletools.systemhelper.Activity.TestActivity` |
| 原生库 | 无 |
| 额外 dex | 无（仅 `classes.dex`） |
| 额外 asset | 仅 `assets/pub.cer` |

### 2.3 APK 签名证书

```text
Subject: C=86, ST=BJ, L=BJ, O=CU, OU=RI, CN=NewDM
Issuer : C=86, ST=BJ, L=BJ, O=CU, OU=RI, CN=NewDM
Serial : 34A8A2C8 (hex) / 883466952 (dec)
算法   : RSA 2048-bit，自签名
有效期 : 2019-03-21 01:59:50 UTC ~ 2069-03-08 01:59:50 UTC
SHA-256: 87:4B:8C:A2:29:7F:53:A3:73:B1:B9:35:C1:34:CB:0E:B1:FF:73:81:E5:44:91:B8:8C:64:3A:6B:9C:46:DB:77
```

`O=CU` 指向 China Unicom；`CN=NewDM` 对应联通“NewDM”设备管理项目。证书国家码写的是 `86`（中国电话区号），不是标准 ISO `CN`，属于证书生成时的不规范写法。

### 2.4 上报加密证书 `pub.cer`

```text
Subject: C=CN, ST=BJ, L=BJ, O=UNICOM, OU=UNICOM, CN=UNICOM
Issuer : C=CN, ST=BJ, L=BJ, O=UNICOM, OU=UNICOM, CN=UNICOM
Serial : 528B9360 (hex) / 1384878944 (dec)
算法   : RSA 1024-bit，自签名
有效期 : 2019-05-24 08:44:27 UTC ~ 2119-04-30 08:44:27 UTC
SHA-256: 81:0C:01:22:BA:6A:F7:A4:B6:A5:92:1F:DB:BB:F9:19:7F:B2:E0:B2:E8:2D:E0:C5:AA:40:D2:8F:1B:7C:65:01
```

该证书只包含公钥，私钥不在 APK 中。代码里还存在 `Cryptography.RSADecrypt()` 引用 `assets/pri.cer`，但 APK 内没有 `pri.cer`，属于死代码。

### 2.5 oat/vdex 说明了什么

- `SystemHelper.odex` 是 ELF 文件，`.dex` 段为 `NOBITS`，真正的 dex 在 `SystemHelper.vdex` 中。
- vdex 头为 `vdex027`，内部是 `cdex001`（CompactDex），对应 Android 12+ 的 ART 格式。
- `strings` 在 odex 中直接找到原始路径：

```text
/product/priv-app/SystemHelper/SystemHelper.apk
```

- odex 元数据：

```text
compiler-filter    = verify
compilation-reason = prebuilt
```

说明它是随系统镜像预编译的**预置特权应用**，不是用户安装的普通 App。

- vdex 中的类描述符（含 support library）与 APK 的 `classes.dex` 基本一致（2470 个全部存在），说明 APK 与 oat 是同一版本，未发现“APK 旧、oat 新”的不一致。

---

## 3. 分析方法与工具

本次分析使用：

| 工具 | 用途 |
|---|---|
| `unzip` | 解包 APK，确认文件组成 |
| `jadx 1.5.6` | 反编译 `classes.dex` 为 Java |
| `androguard 4.1.4` | 解析 Manifest、权限、组件、证书 |
| `openssl` | 解析 `pub.cer` 和 `META-INF/CERT.RSA` |
| `strings` / `readelf` | 分析 odex/vdex 的原始路径、编译参数、字符串 |
| `grep` / Python | 统计 Reader、机型映射、类集合、字段引用 |

反编译产物位于：

```text
/tmp/opencode/sh_src/sources/com/mobiletools/systemhelper/
```

分析限制：

- 只做静态分析，未在真机运行，未验证服务端行为。
- 未向 `dm.wo.com.cn` 发送请求。
- 服务端是否校验 `Time`、是否去重、是否做营销/风控，客户端代码无法证明。
- 本报告只覆盖 2022 年构建的 `1.2-20220907` 历史版本；不同系统版本/不同预置版本（尤其是当前最新版）可能存在差异，不能直接套用本报告结论。

---

## 4. 应用身份与来源

### 4.1 包名与命名

- 包名：`com.mobiletools.systemhelper`
- 应用名：`SystemHelper`
- 证书：`O=CU, OU=RI, CN=NewDM`
- 服务器：`dm.wo.com.cn`（`wo` 是中国联通品牌）
- 旧接口命名空间：`webservice.chinaunicom.com`

这些信息共同指向：**中国联通终端管理/终端注册体系**。

### 4.2 用户可见性

- 没有 `MAIN/LAUNCHER` Activity，桌面无图标。
- 图标是通用 Android 图标。
- 唯一 Activity 是隐藏的 `TestActivity`，用于显示设备信息 JSON。
- 资源中有两条中文文案：

```text
运营商服务（SystemHelper）
运营商可能通过 WLAN 或移动数据网络收集您的设备信息等数据，开启即视为同意联网、访问应用列表和定位。
```

这两条字符串在本 APK 内没有被 Java 代码引用，推测是给 OEM 系统设置里的“运营商服务”开关使用的。实际是否展示、开关名称、开关写入哪个 Settings 键，取决于厂商设置界面。

### 4.3 旧版遗留接口

`WebServiceHelper` 把 URL、命名空间、方法名、SOAP Action 存成 byte 数组，运行时解码。解码结果：

```text
NAMSE_SPACE    = http://webservice.chinaunicom.com/
WEBSERVICE_URL = http://61.148.212.26:8080/bonc_Register/RegisterPort?wsdl
WEBSERVICE_METHOD = GetRegister
SOAP_ACTION    = http://webservice.chinaunicom.com/GetRegister
```

但 `registerDevInfo()` 直接 `return false`，这是旧版 SOAP 注册接口的死代码。`61.148.212.26` 位于中国联通北京地区地址段（具体归属以 whois 为准），`bonc_Register` 可能对应 BONC（东方国信）为联通建设的注册服务。

另外还有两个死代码/默认关闭的接口：

```text
http://dm.wo.com.cn:6002/registerv3/getRegisterLog   # LogPostHelper，未被调用
http://dm.wo.com.cn:18080/public/ip                  # GetIPAddressHttpHelper，GET_IP_ENABLED=false
```

---

## 5. Manifest、组件与权限

### 5.1 组件清单

| 类型 | 组件 | exported | 说明 |
|---|---|---|---|
| Activity | `com.mobiletools.systemhelper.Activity.TestActivity` | `true` | 隐藏的设备信息页；可被任意 App 启动；会触发注册 |
| Receiver | `com.mobiletools.systemhelper.control.OnBootReceiver` | `true` | 开机、延迟注册；priority `2147483647` |
| Receiver | `com.mobiletools.systemhelper.control.ScheduleRegisterReceiver` | 默认 false | 每日 `S` 注册 |
| Receiver | `com.mobiletools.systemhelper.control.AppInfoRegisterReceiver` | 默认 false | 每周 `A` App 统计 |
| Receiver | `com.mobiletools.systemhelper.control.SIMStateReceiver` | `true` | SIM 状态变化 `T` 注册 |
| Receiver | `com.mobiletools.systemhelper.control.ConnectStateReceiver` | `true` | 网络变化，仅打日志 |
| Service | `com.mobiletools.systemhelper.service.RegisterHelperService` | `true` | AIDL 配置服务；**无权限保护** |
| Service | `com.mobiletools.systemhelper.service.RegisterIntentService` | 默认 false | 努比亚/格力等厂商服务的等待与注册 |
| Service | `com.mobiletools.systemhelper.service.RegisterJobService` | 受 `BIND_JOB_SERVICE` 保护 | JobService 壳，基本空实现 |

Manifest 关键片段：

```xml
<application
    android:theme="@style/AppTheme"
    android:label="@string/app_name"
    android:icon="@mipmap/ic_launcher"
    android:name="com.mobiletools.systemhelper.control.DMApplication"
    android:allowBackup="false"
    android:supportsRtl="true"
    android:usesCleartextTraffic="true"
    android:roundIcon="@mipmap/ic_launcher_round"
    android:appComponentFactory="android.support.v4.app.CoreComponentFactory">
```

### 5.2 权限清单

| 权限 | 用途 | 备注 |
|---|---|---|
| `android.permission.INTERNET` | HTTP 上报 | 明文 HTTP |
| `android.permission.ACCESS_NETWORK_STATE` | 判断 WiFi/移动网络 | |
| `android.permission.READ_PHONE_STATE` | 读取电话状态、网络制式、小区 | |
| `android.permission.READ_PRIVILEGED_PHONE_STATE` | 读取 IMEI/IMSI/ICCID 等 | 只有特权系统应用可获得 |
| `android.permission.RECEIVE_BOOT_COMPLETED` | 开机自启 | |
| `android.permission.SCHEDULE_EXACT_ALARM` | 精确闹钟 | |
| `android.permission.ACCESS_COARSE_LOCATION` | 小区/粗定位 | |
| `android.permission.ACCESS_FINE_LOCATION` | 可选 GPS | 默认不启用 |
| `android.permission.ACCESS_BACKGROUND_LOCATION` | 后台定位 | 仅可选 GPS 路径使用 |
| `android.permission.PACKAGE_USAGE_STATS` | App 使用时长/流量 | 特殊 appop |
| `android.permission.QUERY_ALL_PACKAGES` | 枚举已安装应用 | 用于匹配 App 名称/UID |
| `android.permission.READ_EXTERNAL_STORAGE` | 声明但未发现实际使用 | 多余权限 |

它**没有**申请：

```text
READ_SMS / RECEIVE_SMS
READ_CONTACTS
READ_CALL_LOG
CAMERA
RECORD_AUDIO
BIND_ACCESSIBILITY_SERVICE
SYSTEM_ALERT_WINDOW
MANAGE_EXTERNAL_STORAGE
FOREGROUND_SERVICE
WAKE_LOCK
```

### 5.3 自定义权限未被使用

Manifest 定义了：

```xml
<permission
    android:name="com.mobiletools.systemhelper.permission"
    android:protectionLevel="signature"/>
```

但没有任何组件使用 `android:permission="com.mobiletools.systemhelper.permission"`。  
`DeviceManager.getCallerPackageSignHash()` 也写了调用方签名校验逻辑，但从未被调用。

这说明开发者考虑过“只允许同签名/系统应用调用”，但没有实际接上，导致 `RegisterHelperService` 完全裸奔。

---

## 6. 运行机制与触发链

### 6.1 应用启动

`DMApplication.onCreate()`：

```java
if (Build.VERSION.SDK_INT >= 30) {
    DeviceInfoReaderBase.listenNetworkTypeForR(this);
}
```

在 Android 11+ 上注册双卡网络制式监听，用于后续 `NCLS1/NCLS2` 字段。

### 6.2 五类注册事件

| RegType | 触发 | 默认频率 | 含义 |
|---|---|---|---|
| `F` | 首次开机/首次注册 | 一次 | First power-on，首次激活 |
| `B` | 后续每次开机 | 每次开机 | Boot，开机注册 |
| `S` | `ScheduleRegisterReceiver` | 24 小时 | Schedule，日常注册 |
| `T` | SIM 状态变化 | 换卡时 | SIM 变化；只有 ICCID 变化才真正上报 |
| `A` | `AppInfoRegisterReceiver` | 7 天 | App 使用统计 |

### 6.3 开机链路

`OnBootReceiver` 收到 `BOOT_COMPLETED` 或 `QUICKBOOT_POWERON`：

```text
1. 延迟 4 分钟（AlarmHelper.BootAlarmAfter(240000)）
2. 安排 24 小时后的 ScheduleRegisterReceiver
3. 安排 7 天后的 AppInfoRegisterReceiver
4. return
```

4 分钟后，`PendingIntent` 再次触发 `OnBootReceiver`，此时 `intent.getAction()` 为 `null`，跳过开机分支，进入注册流程：

```text
读取 SIM 状态
→ 动态注册 SIMStateReceiver / ConnectStateReceiver
→ 判断网络/SIM 是否就绪
→ 读取 firstPowerOn 偏好
→ 为空则 RegType=F，否则 RegType=B
→ DeviceInfo.getCurDeviceInfo(context, "F"/"B")
```

### 6.4 换卡链路

`SIMStateReceiver` 收到 `SIM_STATE_CHANGED`：

```text
SIM state = 1 (ABSENT) 或 5 (READY)
→ 延迟 6 分钟（AlarmHelper.SIMStateAlarmAfter(360000)）
→ 再次触发自己
→ DeviceInfo.getCurDeviceInfo(context, "T")
→ 只有 ICCID1/ICCID2 变化才真正上报
```

### 6.5 定时链路

- `ScheduleRegisterReceiver`：每次触发后重新安排 24 小时，调用 `DeviceInfo.getCurDeviceInfo(context, "S")`。
- `AppInfoRegisterReceiver`：每次触发后重新安排 7 天，调用 `DeviceInfo.getCurDeviceInfo(context, "A")`。
- 两者在 Android 12+ 上会在结束时调用 `unlistenNetworkTypeForR`。

### 6.6 网络变化

`ConnectStateReceiver` 只打印 `NetWork connected/disconnected`，不上报、不注册。

### 6.7 手动/隐藏入口

`TestActivity` 导出，action 为：

```text
com.mobiletools.systemhelper.activity.testactivity
```

它调用：

```java
DeviceInfo.getCurDeviceInfoJsonForUI(context)
→ DeviceManager.getCurDeviceInfo(context)
→ new QueryAppInfoThread(...).start()
→ RegisterThread
```

因此，**在权限已授予的情况下，打开这个隐藏 Activity 本身就会触发一次完整注册，包括 App 使用统计**。UI 上只显示设备信息 JSON，不显示 AppInfo/SignalInfo，但后台上报包含它们。

### 6.8 配置服务

`RegisterHelperService` 是 AIDL 服务，导出且无权限保护：

```java
setServerAddress(String str)      // 修改上报地址
setScheduleInterval(int i)        // 修改基础间隔，同时设置 AppInfo 间隔 = (i*8)/5
cleanRegisterData()               // 删除 SharedPreferences（不删数据库）
logEnable(boolean z)              // 打开/关闭详细日志
isLogEnable()                     // 查询日志开关
```

这些方法都没有校验调用方。

---

## 7. 数据采集范围

### 7.1 `DeviceInfo` 字段

`DeviceInfo.getJsonString()` 生成如下字段：

| 类别 | 字段 | 说明 |
|---|---|---|
| 设备 | `Manuf` | 厂商 |
| 设备 | `Model` | 机型 |
| 设备 | `HWVersion` | 硬件版本 |
| 设备 | `SWVersion` | 软件/固件版本 |
| 设备 | `OS` | 固定 `Android` |
| 设备 | `OSVersion` | Android 版本 |
| 设备 | `DeviceType` | `000` 手机、`000002` 2G、`000003` 3G、`000004` 4G、`000005` 5G 等 |
| 设备 | `SubType` | 部分机型带 `RAM/ROM/FREE` |
| 标识 | `IMEI1`、`IMEI2` | 双卡 IMEI |
| SIM | `ICCID1/2` | SIM 卡集成电路卡识别码 |
| SIM | `IMSI1/2` | 国际移动用户识别码 |
| SIM | `MSISDN1/2` | 手机号码 |
| SIM | `MNC1/2` | 实际是 MCC+MNC，如 `46001` |
| 卡槽 | `DataSlot` | `1`/`2`/`0` |
| 网络 | `AccType` | `WiFi`/`Mobile`/`Disconnected` |
| 网络 | `NCLS1/2` | GSM/WCDMA/CDMA/LTE/NR/NSA/SA/TD-SCDMA/UNKNOWN |
| 位置 | `CellID1/2` | 蜂窝小区 ID |
| 位置 | `LAC1/2` | 位置区码；CDMA 下可能是经纬度字符串 |
| 业务 | `VolteEnabled1/2` | VoLTE 开关状态 |
| 业务 | `5GEnabled1/2` | 5G 能力/开关状态 |
| 元数据 | `RegType` | F/B/S/T/A |
| 元数据 | `SpecVersion` | 固定 `3.0` |
| 元数据 | `RegVersion` | 应用版本名 `1.2-20220907` |
| 元数据 | `Time` | `yyyy-MM-dd HH:mm:ss` |
| App | `AppInfo` | 仅 `RegType=A` 或 UI 路径 |
| 历史 | `History` | 最多 100 条历史记录 |
| 可选 | `IPv4`、`IPv6` | `GET_IP_ENABLED=true` 时 |
| 可选 | `SignalInfo` | `SIGNAL_ENABLE=true` 时 |

注意：`VoNREnabled` 字段在 `DeviceInfo` 中定义，但没有被赋值，也没有被序列化，实际不上报。

### 7.2 AppInfo 的准确范围

`QueryAppInfoThread.queryAppUsageStatsDescend()`：

1. `pm.getInstalledApplications(0)` 枚举已安装应用，用于匹配包名、UID、应用名。
2. `UsageStatsManager.queryAndAggregateUsageStats(now - 7天, now)` 取最近 **7 天**使用统计。
3. 按 `getTotalTimeInForeground()` 降序排序。
4. 对每个有 UsageStats 的应用生成：

```json
{
  "appLabel": "应用名",
  "pkgName": "包名",
  "runTime": "前台分钟数min",
  "tx1": "SIM1发送KB",
  "rx1": "SIM1接收KB",
  "totalData1": "SIM1总流量KB",
  "tx2": "SIM2发送KB",
  "rx2": "SIM2接收KB",
  "totalData2": "SIM2总流量KB",
  "totalDataWiFi": "WiFi总流量MB"
}
```

关键结论：

- 上报的是**统计窗口内用过的 App**，不是完整安装列表。
- 代码虽然调用了 `getInstalledApplications`，但只用于匹配名称/UID，没有把未使用的 App 全部上传。
- 不读取 App 内容、聊天记录、通知、屏幕、键盘输入。
- 默认窗口是 7 天，不是 24 小时。
- `QueryAppInfoThread` 的 4 参数构造器（可指定起止时间）存在，但当前代码没有使用；两处调用都用 3 参数构造器，即固定最近 7 天。

### 7.3 History 补传

`DatabaseHelper`：

```text
数据库名: systemhelper
表名    : history
字段    : id, jsonString
上限    : 100 条
```

流程：

```text
doEncrpytPost()
→ 查询 history 全部记录
→ deviceInfo.History = JSONArray
→ getJsonString() 把 History 一起序列化
→ POST
→ 成功：clearHistory()
→ 失败：deviceInfo.History = null，把当前记录写回 history
```

因此，在“长期没有 WiFi / 非联通卡”的情况下，本地会积累最多 100 条记录；一旦连上 WiFi，会一次性补传。每条记录都可能包含当时的设备、SIM、蜂窝位置和 App 统计。

### 7.4 SignalInfo 数据库

`SignalDatabaseHelper`：

```text
数据库名: signalinfo
表名    : signal
上限    : 200 条
```

仅在 `SIGNAL_ENABLE=true` 时使用；本样本默认为 `false`。

---

## 8. 上报协议与密码学

### 8.1 请求格式

```http
POST http://dm.wo.com.cn:18080/registerv3?ver=3.0&model=<Model>&manuf=<Manuf>&sign=<Base64(RSA(MD5(json)))>
Content-Type: application/encrypted-json
Content-Length: <len>

<AES/ECB/PKCS5Padding(json, key=MD5(json))>
```

字段说明：

| 部分 | 内容 |
|---|---|
| `ver` | 固定 `3.0` |
| `model` | `DeviceInfo.Model`，URL 编码，明文 |
| `manuf` | `DeviceInfo.Manuf`，URL 编码，明文 |
| `sign` | `URLEncoder.encode(Base64(RSA/ECB/PKCS1Padding(pub.cer, MD5(json))))` |
| body | `AES/ECB/PKCS5Padding(json, key=MD5(json))` |

### 8.2 加密流程

```text
jsonBytes = json.getBytes("UTF-8")
md5       = MD5(jsonBytes)                     // 16 字节
sign      = RSA_encrypt(pub.cer, md5)          // 128 字节（1024-bit）
signB64   = Base64(sign)
body      = AES_ECB_PKCS5(jsonBytes, key=md5)
url       = server + "?ver=3.0&model=...&manuf=...&sign=" + URLEncode(signB64)
```

服务端用私钥解密 `sign` 得到 MD5，再用它作为 AES 密钥解密 body。  
这个设计同时承担“密钥传输”和“完整性校验”的作用，但**不是签名**：任何拿到 `pub.cer` 的人都能生成同样的 `sign`，因此没有客户端身份认证。

### 8.3 成功/失败判定

`HttpEncryptHelper`：

- 连接超时 10 秒，读取超时 15 秒。
- 只检查 HTTP 状态码。
- `200` → 成功。
- 其他 → 失败，但 `RegisterThread` 对 `416` 特殊处理为成功。
- **不读取响应体**，因此不存在“服务端下发指令”的通道。

### 8.4 网络条件

`RegisterThread.register()`：

```text
1. checkIMEI(IMEI1) && checkIMEI(IMEI2)
   - null/空 → 通过
   - 长度必须 15
   - 必须全数字
2. isNetworkConnected()
3. isWifiConnected() → 直接上报
4. 否则：
   - !isRoamingNow()
   - isUnicomNetwork(deviceInfo)  // 当前数据卡 MNC ∈ {46001,46006,46009}
   - 两者都满足才上报
5. 否则写入 SQLite，不上报
```

这解释了“插移动卡也会上报”的现象：只要连着 WiFi，就不检查 SIM 运营商。

### 8.5 伪匿名化

`DeviceManager.sortAndAnonymousSubscriber()`：

1. 如果 `IMEI1 > IMEI2`（字典序），交换两张卡的所有字段，保证 IMEI 排序稳定。
2. 对每张卡：
   - 如果 `MNC` 非空且不是联通（`46001/46006/46009`）：
     - `ICCID = MD5(ICCID)`
     - `MSISDN = MD5(MSISDN)`
     - `IMSI = MD5(IMSI)`
     - `CellID = MD5(CellID)`
     - `LAC = MD5(LAC)`

问题：

- 只在 `MNC` 非空时哈希；如果 SIM 存在但 `getNetworkOperator()` 返回空，可能直接发送原始值。
- `IMEI` 始终不哈希，仍可唯一识别设备。
- 手机号、ICCID 熵很低，MD5 很容易被字典/枚举还原。
- 哈希值仍是稳定标识，可长期关联同一用户。
- 哈希只发生在客户端，服务端仍可做关联分析。

### 8.6 密码学评估

| 问题 | 影响 |
|---|---|
| 明文 HTTP | 机型、厂商、时间、包大小可见；可被阻断、重放、流量分析 |
| RSA 1024-bit | 按现代标准偏弱；证书有效期到 2119 年 |
| AES-ECB | 确定性加密，无 IV；相同明文得到相同密文 |
| `sign` 不是签名 | 无客户端认证，任何人都能生成 |
| 客户端无 nonce/防重放 | 请求可被原样重放 |
| 无 TLS | 无服务端认证，可被中间人阻断/重定向 |
| 伪匿名化弱 | MD5 + 条件不完整 + IMEI 明文 |

---

## 9. 多厂商适配

### 9.1 规模

| 项目 | 数量 |
|---|---:|
| `DeviceInfoReader` 类 | 58 |
| `DEV_MANUF_MAPS` 机型映射 | 260 |
| 反编译出的 App Java 文件 | 101 |
| 反编译出的总 Java 文件（含 support lib） | 735 |

### 9.2 活跃品牌映射

| 品牌 | 映射数量 | 说明 |
|---|---:|---|
| Xiaomi | 94 | 仅列出的机型；`XIAOMI_4G_5G_PHONE_INTERFACE=false` 时不动态扩展 |
| OPPO | 82 | 仅列出的机型 |
| vivo | 20 + 动态 | `ro.product.manufacturer=vivo` 时所有机型都映射 |
| realme | 11 + 动态 | 所有 realme 机型都映射 |
| Samsung | 6 + 动态 | 所有 Samsung 机型都映射 |
| Hisense | 7 | 列出机型 |
| ZTE | 4 | 列出机型 |
| Lenovo | 4 | 列出机型 |
| OnePlus | 3 | 列出机型 |
| TDTECH | 3 | 列出机型 |
| nubia | 2 | 列出机型 |
| Meizu | 2 | 列出机型 |
| Huawei | 1（EVR-AN00） | 只覆盖一个机型 |
| 其他 | 各 1 | Coolpad、Gionee、Konka、TCL、PTAC、HZTL、Liantong、EWPE、YIK、TOSOT、JingLing、5G HYUN 等 |

重点：**vivo、Samsung、realme 是动态映射所有机型**，不是只覆盖运营商定制机。只要这三个品牌的系统里预置了这个 App，它就会走对应 Reader，而不是被机型白名单挡住。Xiaomi/OPPO 则主要是列出的 94/82 个机型。

### 9.3 适配手段

| 品牌/平台 | 手段 |
|---|---|
| 通用 | 反射 `TelephonyManager` 隐藏方法：`getImei(int)`、`getSubscriberId(int)`、`getSimSerialNumber(int)`、`getLine1NumberForSubscriber(int)`、`getCellLocationForSlot(int)` |
| 努比亚 | 绑定 `com.android.phone/com.android.phone.nubia.NBExtTelephonyService` |
| 格力 | 绑定 `com.gree.telephonymanager/com.gree.telephonymanager.GreeTelephonyManagerService` |
| MTK | `com.mediatek.internal.telephony.ITelephonyEx` / `phoneEx` |
| OPPO/realme/一加 | `ColorOSTelephonyManager` |
| 小米 | `miui.telephony.TelephonyManagerEx` |
| vivo | `vivoTelephonyApi`、`ro.vivo.*` 属性 |
| 中兴 | `com.dmyk.android.telephony.DmUnicomAbsTelephonyManager` |
| 三星 | `getTelephonyProperty`、`getMsisdn` 等隐藏方法 |
| 华为 | `ITelephonyEx.getSvlteImei`、`ro.product.hardwareversion` |

目的就是绕过 Android 对双卡 IMEI/IMSI/ICCID/MSISDN/小区信息的限制，把两张卡的信息都读出来。

### 9.4 死代码

58 个 Reader 中，很多并没有被 `DEV_MANUF_MAPS` 映射到，属于不可达代码。例如：

```text
DeviceInfoReaderLETV
DeviceInfoReaderBROR
DeviceInfoReaderOnefive
DeviceInfoReaderOYSIN
DeviceInfoReaderBenWee
DeviceInfoReaderINTKI
DeviceInfoReaderQIKU
DeviceInfoReaderEAMEY
DeviceInfoReaderORANGE
DeviceInfoReaderKTOUCH
DeviceInfoReaderSHOWN
DeviceInfoReaderYuLong
DeviceInfoReaderKINGSUN
DeviceInfoReaderLEPHONE
DeviceInfoReaderSINTAVE
DeviceInfoReaderPPTV
DeviceInfoReaderBestSonny
DeviceInfoReaderSOP
DeviceInfoReaderPHICOMM
DeviceInfoReaderSpreadtrum
DeviceInfoReaderChangHong
DeviceInfoReaderPHILIPS
DeviceInfoReaderBee
DeviceInfoReaderChuiZi
DeviceInfoReaderPROTRULY
DeviceInfoReaderHAIPAINOBLE
DeviceInfoReaderNOAIN
DeviceInfoReaderMfox
DeviceInfoReaderXiaolajiao
DeviceInfoReaderMOTO
...
```

这不影响“该历史版本实际覆盖机型”的结论，但说明代码是从一个更大的多厂商适配框架裁剪/演化而来的。

---

## 10. 同意机制与隐私问题

### 10.1 同意开关只控制“是否上传”，不控制“是否采集”

`GlobalSetting.isUserPermissionOpen` 默认是 `true`。`RegisterThread.run()`：

```java
if (GlobalSetting.isUserPermissionOpen) {
    handleRegisterResult(register(deviceInfo));      // 上报
} else {
    databaseHelper.insertRecord(deviceInfo.getJsonString()); // 只落库
}
```

也就是说，开关为 false 时，**它仍然会读取设备信息并写入本地数据库**，只是不 POST。等开关变为 true，这些记录会作为 `History` 补传。

更关键的是：多数 Reader 只是把 `isUserPermissionOpen` 设成检查结果，然后**继续读取**，并不 return。例如：

- `DeviceInfoReaderXiaomi.read()`：设置 flag 后继续读取。
- `DeviceInfoReaderOPPO.read()`：设置 flag 后继续读取。
- `DeviceInfoReaderSamSung.read()`：设置 flag 后继续读取。
- `DeviceInfoReaderRealme.read()`：设置 flag 后继续读取。

只有少数 Reader 会在 false 时提前 return：

- `DeviceInfoReaderVIVO.read()`：`if (!isUserPermissionOpen) { log; return; }`
- `DeviceInfoReaderOFeng.read()`：同上。

### 10.2 各品牌的“同意”检查并不一致

| 检查方式 | 代表机型/品牌 |
|---|---|
| 只检查 `device_provisioned == 1`（开机向导完成） | Xiaomi、OPPO、Realme、OnePlus、Samsung、TCL、Coolpad、Gree、HZTL、JingLing、Liantong、PTAC、TDTECH、YinKe |
| `device_provisioned && operator_service_improve_plan == 1` | vivo、Hisense、Konka、Meizu |
| `operator_service_improve_plan == 1` | Nubia、EWPE |
| `dm_user_agreement == 1` | ZTE、Baidu（sprd） |
| `device_provisioned && operator_registration_switch == 1` | Gionee |
| `agree_unicom == 1`，默认值就是 `1` | Lenovo |
| 永远返回 true | OFeng |
| 完全没有检查，默认 true | Huawei（EVR-AN00）以及不少未激活/旧 Reader |

含义：

- 在 Xiaomi/OPPO/Samsung/realme/OnePlus 等主流机型上，**只要用户完成了开机向导，就被视为满足条件**，并没有单独检查“运营商服务改进计划”或隐私协议。
- Lenovo 的 `agree_unicom` 默认值是 1，等于默认同意。
- Huawei 唯一映射的机型完全没有检查。
- 资源里的“开启即视为同意”文案，和代码实际检查的开关并不完全对应。

### 10.3 数据保留问题

`cleanRegisterData()` 只删除 SharedPreferences 文件：

```text
/data/data/com.mobiletools.systemhelper/shared_prefs/com_mobiletools_systemhelper_preference.xml
```

**不会删除**：

```text
/data/data/com.mobiletools.systemhelper/databases/systemhelper   (history 表)
/data/data/com.mobiletools.systemhelper/databases/signalinfo     (signal 表)
```

因此即使调用“清理注册数据”，历史设备/SIM/位置/App 记录仍然留在本地，后续仍可能被补传。数据库没有加密；`allowBackup=false` 只能挡住普通备份，root/特权应用仍可读取。

### 10.4 默认关闭但仍存在的采集能力

以下开关在代码中从未被设为 true，因此本样本默认不执行：

| 开关 | 默认 | 能力 |
|---|---|---|
| `SIGNAL_ENABLE` | false | 采集 `ssRsrp/ssRsrq/ssSinr`、GPS 经纬度、信号历史（最多 200 条） |
| `GET_IP_ENABLED` | false | 请求 `http://dm.wo.com.cn:18080/public/ip`，上报公网 IPv4 和本机 IPv6 |
| `FORCE_OPEN_VOLTE` | false | 通过隐藏 API `ImsMmTelManager.setAdvancedCallingSettingEnabled(true)` 强制打开 VoLTE |
| `XIAOMI_4G_5G_PHONE_INTERFACE` | false | 通过 MIUI 接口判断 5G 能力 |

虽然默认关闭，但这些代码路径说明它具备相应能力；未来版本或修改配置可能启用。

### 10.5 隐私影响

从隐私角度看，它具备以下特征：

- 预置特权系统应用，用户无法正常卸载。
- 采集 IMEI/IMSI/ICCID/MSISDN 等强标识，可直接关联到实名登记的用户。
- 采集 CellID/LAC，可用于粗定位和历史轨迹分析。
- 采集 App 使用时长和流量，可推断用户行为、偏好、作息。
- 默认每 7 天上传一次 App 统计，失败可积累最多 100 条记录后一次性补传。
- 同意检查在多数主流机型上只等同于“开机向导完成”，且采集不一定受开关控制。
- 披露文案只出现在系统设置资源里，App 本身没有隐私政策、同意对话框或退出界面。
- 明文 HTTP + 弱伪匿名化，增加第三方流量分析和关联风险。

---

## 11. 安全攻击面

### 11.1 攻击面汇总

| 严重度 | 问题 | 影响 |
|---|---|---|
| 高 | `RegisterHelperService` 导出且无权限保护 | 任意 App 可改服务器地址、改定时间隔、清数据、开日志 |
| 中高 | `TestActivity` 导出 | 任意 App 可启动，触发完整注册并显示 IMEI/IMSI |
| 中 | `OnBootReceiver` / `SIMStateReceiver` 导出 | 显式广播可触发注册流程 |
| 中 | 明文 HTTP + RSA-1024 + AES-ECB | 流量分析、重放、中间人阻断/重定向 |
| 中 | 同意/采集逻辑 | 未同意也可能本地采集，后续补传 |
| 低 | `cleanRegisterData` 不删数据库 | 隐私数据残留 |
| 低 | `logEnable` 可被任意 App 打开 | 敏感 JSON 进入 logcat |
| 低 | `READ_EXTERNAL_STORAGE` 多余 | 权限最小化问题 |
| 低 | 闹钟类型、不可达分支、回调泄漏等 | 功能/稳定性问题 |

### 11.2 导出的 `RegisterHelperService`

Manifest：

```xml
<service
    android:name="com.mobiletools.systemhelper.service.RegisterHelperService"
    android:exported="true">
    <intent-filter>
        <action android:name="com.mobiletools.systemhelper.service.IRegisterHelperService"/>
    </intent-filter>
</service>
```

没有 `android:permission`。AIDL 方法也没有检查调用方：

- `setServerAddress(String)`：任意 App 可以把上报地址改到自己的服务器。
  - 正文用联通公钥体系加密，攻击者未必能解密；
  - 但可以让联通收不到遥测；
  - 可以收集机型/厂商/时间/包大小等元数据；
  - 可以返回 200 让 App 误以为成功并清空 History；
  - 可以进行重放/流量分析。
- `setScheduleInterval(int)`：可以设置负数或极小值，导致闹钟立即反复触发，形成耗电/DoS 循环。
- `cleanRegisterData()`：删除 prefs，但不删数据库；还会重置 `firstPowerOn`，导致下次重新按“首次开机”注册。
- `logEnable(true)`：打开详细日志，`MyLog.d` 会把完整设备 JSON（含 IMEI/IMSI/ICCID）打到 logcat。

代码里定义了 `com.mobiletools.systemhelper.permission`（signature 级），但**没有应用到任何组件**；`DeviceManager.getCallerPackageSignHash()` 也写了但从未调用。说明开发者考虑过调用方校验，但没有接上。

### 11.3 导出的 `TestActivity`

- 任何 App 都可以启动。
- 会申请 `READ_PHONE_STATE`、`ACCESS_COARSE_LOCATION`、`ACCESS_NETWORK_STATE`。
- 会显示 IMEI/IMSI/ICCID/MSISDN/CellID 等 JSON。
- 在权限已授予时，会触发一次完整注册（包括 App 统计）。

### 11.4 导出的广播接收器

- `OnBootReceiver`：任何 App 可以发显式广播。如果 action 不是 `BOOT_COMPLETED/QUICKBOOT_POWERON`，它会走 SIM 状态分支，最终触发注册。
- `SIMStateReceiver`：任何 App 可以发显式 `SIM_STATE_CHANGED` 广播，触发 `T` 类型注册（只有 ICCID 变化才真正上报）。
- `ConnectStateReceiver`：导出但只打日志，影响较小。

### 11.5 协议与加密弱点

- 明文 HTTP，无 TLS，无服务端认证。
- RSA 1024-bit，AES-ECB，无 IV，客户端无 nonce/防重放。
- `sign` 是公钥加密，不是签名，没有客户端认证。
- 伪匿名化使用 MD5，且条件不完整（MNC 为空时不哈希）。
- 这些不是“远程入侵”漏洞，但会导致隐私泄露、流量分析、重放和中间人阻断/重定向。

### 11.6 其他代码质量问题

- `DeviceInfoReaderBase.read()` 中 `readAndroidR` 分支不可达（`SDK>=26` 已经先命中 `readGeneric26`）。
- `unlistenNetworkTypeForR` 的 null 判断用错了对象，可能导致回调泄漏。
- `AlarmHelper` 使用 `ELAPSED_REALTIME`（type 2）而不是 `ELAPSED_REALTIME_WAKEUP`，设备休眠时闹钟可能不触发。
- `DMTelephonyCallback` 在 `SIGNAL_ENABLE` 为 true 且 `getLastKnownLocation` 为 null 时，会在 `while` 循环里反复 `requestLocationUpdates`，逻辑有问题（默认关闭，不会触发）。
- `DeviceInfoReaderKTOUCH` 把 `ContactsContract.CommonDataKinds.Phone[]` 当作普通对象数组用，容易让人误以为它读联系人；实际上没有读联系人。

---

## 12. 它不是什么

为了避免被网络传言误导，明确以下几点：

| 传言 | 本样本事实 |
|---|---|
| “反诈 App” | 不是。证书 `O=CU/OU=RI/CN=NewDM`，服务器 `dm.wo.com.cn`，没有国家反诈中心相关包名/域名/接口 |
| “录屏/截屏” | 没有 `MediaProjection`、`AccessibilityService`、`SYSTEM_ALERT_WINDOW`、通知监听等代码。网上说的“每 3 秒录屏”是小米另一个“系统安全组件”，不是这个 App |
| “读短信/联系人/通话记录” | 没有 `READ_SMS`、`RECEIVE_SMS`、`READ_CONTACTS`、`READ_CALL_LOG` 权限 |
| “读通知/键盘输入” | 没有 `NotificationListenerService`、无障碍服务、输入法相关代码 |
| “麦克风/摄像头/文件窃取” | 没有 `RECORD_AUDIO`、`CAMERA`、`MANAGE_EXTERNAL_STORAGE`；`READ_EXTERNAL_STORAGE` 声明了但代码中没有实际文件读取（除了 `/proc/meminfo`、`/etc/version.conf`、`/sys/nubia_hw_version/...` 这类系统信息文件） |
| “远程控制/锁机/下发指令” | 只发 POST，不解析响应体；没有 MQTT/WebSocket/推送/SMS 指令通道；没有 `DevicePolicyManager`、`PackageInstaller`、`Runtime.exec`、动态加载 |
| “第三方广告/分析 SDK” | 未发现；网络请求只指向 `dm.wo.com.cn` 和代码里遗留的联通旧地址 |

准确地说：它是一个**单向的、预置的、特权级运营商遥测/注册组件**，不是 RAT，也不是完整 MDM（不能远程锁机/擦除/装应用）。

补充：代码里有一个未被调用的 `isHaveReceiveSmsAndReadPhoneState()` 方法，用来检查“同时有 RECEIVE_SMS + READ_PHONE_STATE”的应用（还排除了 `com.derekjiang.smsforward`），但它没有被使用；这不代表它读短信。

---

## 13. 用途推断

从字段和触发时机推断，联通/厂商主要用它做：

1. **终端注册与激活统计**
   - 首次开机 `F`、后续开机 `B`；
   - 确认设备激活、机型、IMEI、SIM、软件版本。

2. **网络与业务质量统计**
   - MCC+MNC、网络制式、CellID/LAC、VoLTE/5G 开关状态；
   - 用于网络优化和业务开通核验。

3. **渠道/窜货管理**
   - 首次开机 + 换卡 `T` + 蜂窝位置；
   - 可判断设备是否在预期区域/渠道激活。这是国内运营商定制机常见的“防窜货”需求。

4. **App 使用与流量画像**
   - 每周上报用过的 App、前台时长、移动/WiFi 流量；
   - 可能用于用户画像、营销分析或异常使用检测。

5. **终端能力核验**
   - VoLTE/5G 能力、双卡数据卡槽、RAM/ROM 等；
   - 用于终端入库和业务适配。

客户端代码只能证明“采集并上报”，**不能证明服务端的具体用途**；服务端是否做营销、风控或渠道审计，需要服务端数据才能确定。

---

## 14. 与公开报道及当前版本的差异

### 14.1 这是 2022 年的历史版本

本报告分析的是 **`1.2-20220907`（versionCode 3）**，按版本名推断构建于 **2022-09-07**。它属于较早的预置组件版本，不是 2024–2026 年当前最新版本。

因此，本报告与网上一些针对“当前最新版”的分析出现差异，是正常的。当前最新版本可能已经：

- 更换上报域名、协议或加密方式；
- 增加/删除采集字段；
- 调整默认上报周期；
- 扩展或收缩厂商适配范围；
- 修改同意逻辑和系统设置开关；
- 修复导出组件、明文 HTTP 等安全问题；
- 增加新的功能或移除旧代码。

**本报告不能证明当前最新版本仍然存在同样的问题。** 如果要判断当前版本，必须重新提取对应 APK/oat 并重新分析。

### 14.2 与公开报道的差异

| 公开说法 | 本样本（2022 历史版本）事实 |
|---|---|
| “统计过去 24 小时的 App 使用” | 本样本 `DEFAULT_APP_INFO_INTERVAL=604800000`，即最近 **7 天** |
| “每 2 小时联网一次” | 本样本默认 `DEFAULT_SCHEDULE_INTERVAL=86400000`，即 **24 小时**；可通过 helper service 调整 |
| “会录屏” | 本样本没有录屏能力；那是另一个小米系统组件 |
| “反诈程序” | 本样本是联通 DM/终端注册，不是反诈 |
| “只针对联通定制机” | 本样本对 vivo/Samsung/realme 动态映射所有机型；Xiaomi/OPPO 覆盖大量机型；不是只限联通定制机 |

不同系统版本、不同预置版本可能有不同的默认间隔和功能，以上以本样本 `1.2-20220907` 为准。

---

## 15. IOC 汇总

### 15.1 网络 IOC

| 类型 | 值 | 状态 | 说明 |
|---|---|---|---|
| 域名 | `dm.wo.com.cn` | 活跃 | 联通 DM 平台 |
| URL | `http://dm.wo.com.cn:18080/registerv3` | 活跃 | 主上报接口 |
| URL | `http://dm.wo.com.cn:18080/public/ip` | 默认关闭 | 公网 IP 查询，`GET_IP_ENABLED=false` |
| URL | `http://dm.wo.com.cn:6002/registerv3/getRegisterLog` | 死代码 | 日志上传，未调用 |
| IP | `61.148.212.26:8080` | 死代码 | 旧版 SOAP 注册接口 |
| URL | `http://61.148.212.26:8080/bonc_Register/RegisterPort?wsdl` | 死代码 | 旧版联通注册服务 |
| 命名空间 | `http://webservice.chinaunicom.com/` | 死代码 | 旧版 SOAP 命名空间 |
| SOAP Action | `http://webservice.chinaunicom.com/GetRegister` | 死代码 | 旧版 SOAP Action |

### 15.2 文件/组件 IOC

| 类型 | 值 |
|---|---|
| 包名 | `com.mobiletools.systemhelper` |
| 应用名 | `SystemHelper` |
| 版本 | `1.2-20220907` |
| 系统路径 | `/product/priv-app/SystemHelper/SystemHelper.apk` |
| 服务 | `com.mobiletools.systemhelper.service.RegisterHelperService` |
| 服务 Action | `com.mobiletools.systemhelper.service.IRegisterHelperService` |
| Activity | `com.mobiletools.systemhelper.Activity.TestActivity` |
| Activity Action | `com.mobiletools.systemhelper.activity.testactivity` |
| 开机 Receiver | `com.mobiletools.systemhelper.control.OnBootReceiver` |
| SIM Receiver | `com.mobiletools.systemhelper.control.SIMStateReceiver` |
| 网络 Receiver | `com.mobiletools.systemhelper.control.ConnectStateReceiver` |
| 数据库 | `systemhelper`（`history` 表）、`signalinfo`（`signal` 表） |
| 偏好文件 | `com_mobiletools_systemhelper_preference.xml` |

### 15.3 证书 IOC

| 证书 | Subject | SHA-256 |
|---|---|---|
| APK 签名 | `C=86, ST=BJ, L=BJ, O=CU, OU=RI, CN=NewDM` | `87:4B:8C:A2:29:7F:53:A3:73:B1:B9:35:C1:34:CB:0E:B1:FF:73:81:E5:44:91:B8:8C:64:3A:6B:9C:46:DB:77` |
| 上报公钥 | `C=CN, ST=BJ, L=BJ, O=UNICOM, OU=UNICOM, CN=UNICOM` | `81:0C:01:22:BA:6A:F7:A4:B6:A5:92:1F:DB:BB:F9:19:7F:B2:E0:B2:E8:2D:E0:C5:AA:40:D2:8F:1B:7C:65:01` |

---

## 16. 处置建议

> 以下仅从技术角度给出，是否执行取决于设备所有权、当地法律和保修政策。

### 16.1 普通用户

- 这是 `/product/priv-app` 的预置应用，普通用户**无法正常卸载**；`adb uninstall` 对系统应用通常无效。
- 在系统设置中查找“运营商服务（SystemHelper）”开关并关闭。
  - 但根据代码，这个开关在多数机型上只控制上传，不控制本地采集。
  - 部分机型根本不检查它。
- 如果不改系统，最直接的是**阻断域名**：
  - 在 DNS/hosts/防火墙层面把 `dm.wo.com.cn` 指向黑洞；
  - 这样 App 无法上报，但本地仍可能继续采集/落库。
- 检查以下目录（需要 root/特权）：
  - `/data/data/com.mobiletools.systemhelper/shared_prefs/`
  - `/data/data/com.mobiletools.systemhelper/databases/systemhelper`
  - `/data/data/com.mobiletools.systemhelper/databases/signalinfo`

### 16.2 Root/系统修改

- 删除 `/product/priv-app/SystemHelper/` 下的 APK 和 oat。
- 或禁用以下组件：
  - `RegisterHelperService`
  - `OnBootReceiver`
  - `SIMStateReceiver`
  - `TestActivity`
- 注意：可能影响双卡识别、VoLTE 开通、运营商业务、终端注册等功能，删除前建议备份。

### 16.3 企业/取证

- 保留 APK、oat、`shared_prefs`、`databases` 作为证据。
- 记录 `dm.wo.com.cn` 的 DNS 解析和网络流量（如有）。
- 如需验证上报内容，可在隔离环境用测试设备 + 自建 HTTP 服务观察请求；不要向真实联通服务器发送伪造数据。

---

## 17. 复现命令与证据索引

### 17.1 解包与反编译

```bash
# 解包
unzip -o SystemHelper.apk -d sh_extract

# jadx 反编译
jadx -d sh_src --show-bad-code -j 8 SystemHelper.apk

# 查看 Manifest/权限/组件（androguard）
python3 - <<'PY'
from androguard.core.apk import APK
a = APK('SystemHelper.apk')
print(a.get_package())
print(a.get_permissions())
print(a.get_activities())
print(a.get_services())
print(a.get_receivers())
PY
```

### 17.2 证书

```bash
openssl x509 -in assets/pub.cer -inform DER -text -noout
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -print_certs -text
```

### 17.3 oat/vdex

```bash
strings -a oat/arm64/SystemHelper.odex | grep -E 'product/priv-app|compiler-filter|prebuilt'
xxd -l 64 oat/arm64/SystemHelper.vdex
readelf -S oat/arm64/SystemHelper.odex
```

### 17.4 关键代码位置

```text
control/OnBootReceiver.java
control/SIMStateReceiver.java
control/ScheduleRegisterReceiver.java
control/AppInfoRegisterReceiver.java
control/ConnectStateReceiver.java
control/RegisterThread.java
control/DeviceInfo.java
control/QueryAppInfoThread.java
control/DMTelephonyCallback.java
control/DMPhoneStateListener.java
device/DeviceManager.java
device/DeviceInfoReaderBase.java
device/DeviceInfoReaderXiaomi.java
device/DeviceInfoReaderOPPO.java
device/DeviceInfoReaderVIVO.java
device/DeviceInfoReaderSamSung.java
device/DeviceInfoReaderRealme.java
device/DeviceInfoReaderOnePlus.java
service/RegisterHelperService.java
service/IRegisterHelperService.java
utils/GlobalSetting.java
utils/RegisterUtils.java
utils/Cryptography.java
utils/RSAHelper.java
utils/HttpEncryptHelper.java
utils/DatabaseHelper.java
utils/SignalDatabaseHelper.java
utils/WebServiceHelper.java
utils/LogPostHelper.java
utils/GetIPAddressHttpHelper.java
```

### 17.5 关键字段/常量

```java
GlobalSetting.DEFAULT_SERVER_ADDRESS   = "http://dm.wo.com.cn:18080/registerv3";
GlobalSetting.GET_WIFI_IP_SERVER_ADDRESS = "http://dm.wo.com.cn:18080/public/ip";
GlobalSetting.DEFAULT_SCHEDULE_INTERVAL = 86400000L;   // 24h
GlobalSetting.DEFAULT_APP_INFO_INTERVAL = 604800000L;  // 7d
GlobalSetting.DEFAULT_SIGNAL_INFO_INTERVAL = 720000L;  // 12min
GlobalSetting.SIGNAL_ENABLE = false;
GlobalSetting.GET_IP_ENABLED = false;
GlobalSetting.FORCE_OPEN_VOLTE = false;
GlobalSetting.XIAOMI_4G_5G_PHONE_INTERFACE = false;
GlobalSetting.isUserPermissionOpen = true;
```

### 17.6 证据分级

| 级别 | 内容 |
|---|---|
| 确认 | 包名、版本、权限、组件、Manifest、证书、服务器 URL、加密流程、默认间隔、数据库结构、系统路径 |
| 高置信推断 | 用途为联通终端注册/遥测、渠道激活管理、App 使用画像、同意机制偏弱 |
| 未确认 | 服务端具体用途、实际部署范围、OEM 设置界面是否展示开关、服务端是否校验时间/去重 |

---

## 18. 结论

> **再次强调：以下结论仅适用于 2022 年构建的 `1.2-20220907` 历史版本，不代表 2024–2026 年的当前最新版本。**  
> 当前最新版本可能已经修改了域名、协议、字段、周期、权限、同意逻辑或修复了相关问题；判断当前版本必须重新提取实际 APK/oat 并重新分析。

`SystemHelper` 是一个由中国联通相关方签名的、预置在系统 `/product/priv-app` 的**终端管理/遥测组件**。它的核心行为是：

```text
采集设备、SIM、蜂窝位置、网络/VoLTE/5G 状态、App 使用与流量
→ 加密（AES-128-ECB + RSA-1024）
→ 通过明文 HTTP 上报到 dm.wo.com.cn:18080/registerv3
→ 失败落库，下次作为 History 补传
```

它具备明显的隐私采集和用户画像能力：

- 采集 IMEI/IMSI/ICCID/MSISDN 等强标识；
- 采集 CellID/LAC，可用于粗定位；
- 采集 App 前台时长和流量；
- 默认每日基础注册、每 7 天 App 统计；
- 失败可积累最多 100 条记录后一次性补传；
- 同意检查在多数主流机型上只等同于“开机向导完成”，且采集不一定受开关控制。

同时存在安全问题：

- 导出的 `RegisterHelperService` 无权限保护，任意 App 可改服务器地址、改定时间隔、清数据、开日志；
- 导出的 `TestActivity` 可被任意 App 启动，并触发完整注册；
- 导出的 `OnBootReceiver` / `SIMStateReceiver` 可被显式广播触发；
- 明文 HTTP、RSA-1024、AES-ECB、无防重放、弱伪匿名化。

但它**不是**反诈 App，**不是**录屏/远控木马，**没有**读短信/联系人/通知/键盘/麦克风/摄像头，**没有**远程控制/锁机/下发指令。准确地说，它是一个**单向的、预置的、特权级运营商遥测/注册组件**，而不是 RAT 或完整 MDM。

---

*报告完。*
