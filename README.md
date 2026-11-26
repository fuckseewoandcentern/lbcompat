# LyricsBlossom Linux 兼容层

这个仓库是 LyricsBlossom 的 Linux 运行层。它加载 arm64 Mach-O，在 x86-64 Linux 上执行，并把程序用到的三套 macOS 接口换成这台机器上的对应物：

- 客机指令由解释器执行。解释器是语义基准。旁边的块缓存把不写标志的整数运算和一部分访存直接编成 x86-64，其余指令仍调用同一套解释器。
- Metal 设备、命令缓冲和渲染通道在创建时记下来，提交时落到 Vulkan。无窗口环境使用 lavapipe 离屏读回。
- 程序自己会拉起 `mediasession-adapter` 并读一行一行的 JSON。兼容层把这次 `posix_spawn` 换成 `lb-mpris-bridge`，桥从 MPRIS（或一份夹具）填出程序已经在解析的字段。

## 准备程序

分卷先按 `.001` 到 `.010` 放在同一目录，再解出来。兼容层不携带、也不应该携带这个 `.app`、里面的字体和 metallib。

```bash
7z x LyricsBlossom-arm.7z.001 -o/tmp/lyricsblossom
```

## 构建

```bash
cmake -S . -B /tmp/lbcompat-build -DCMAKE_CXX_COMPILER=g++
cmake --build /tmp/lbcompat-build -j
```

没有显示、也没有硬件 Vulkan 时，先指定 lavapipe：

```bash
export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json
export VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json
```

## 运行

```bash
/tmp/lbcompat-build/lbcompat /tmp/lyricsblossom/LyricsBlossom-arm/LyricsBlossom.app
```

有 `DISPLAY` 时，窗口出现后会把最近一帧贴上去。没有显示时设置 `LB_FRAME_OUT=/tmp/frame.ppm`，每次提交写一张 PPM。`LB_MAX_INSNS` 限制客机指令数。`LB_TRACE=1` 会把经过的桩函数和选择子打出来。`LB_RUNLOOP` 是 `NSApplication run` 在返回前通知委托的次数，默认只通知一次，避免把调用线程停住。

要在没有会话总线时喂一首歌，写一份夹具再让桥读它：

```text
title=Night Drive
artist=Ada
album=City
status=Playing
length=180000000
position=5000000
player=spotify
```

`LB_MPRIS_FIXTURE` 指向这个文件。`player` 会映射成程序认识的包名：Spotify 是 `com.spotify.client`，网易云是 `com.netease.163music`，QQ 音乐是 `com.tencent.QQMusicMac`。桥的标准输入接受 `TARGET`、`REFRESH`、`SEND` 和 `SEEK`。

## 边界

客机看到的是 Darwin 的 open 标志、`mmap` 标志、144 字节 `stat` 和独立的 errno。进入入口之前，按 `__TEXT,__init_offsets` 的顺序执行静态初始化；其中一项自己出错时记下来并继续后面的项。ObjC 消息能落到镜像里的客机实现，也能落到这里准备的 Foundation、AppKit 和 Metal 对象。没单独写的选择子按属性读写处理。`std::locale` 使用一份 C 区域的字符分类表，`use_facet` 返回的刻面在变换字符串时按原样写回。

Metal 着色器只覆盖一条通用路径：清屏，加上按顶点序号画出的三角形。程序自带的 MSL / metallib 不会被完整编译，玻璃效果不会和 macOS 上逐像素相同。CoreAudio 的进程 tap 返回成功，不采集真实 PCM。libc++ 里没有逐个对接的符号会返回 0，并在结束时列出来。

SHA256 向量指令和个别后期才碰到的编码，以解释器当前的实现为准；遇到未实现的指令时，运行会停在该指令的地址上。

本仓库以 GNU GPL v3 或更高版本授权。
