# ida-swift-demangle

这是一个修改Swift函数的IDA插件。它目前只适用于ELF文件。欢迎pr支持其他格式。
需要swift-demangle二进制文件，Mac安装xcode后就会有这个命令，Windows需要将项目内的.dll、.exe文件移动到插件相同目录

目前只支持macOS、Windows 64位，目前只在macOS-IDA7.0测试成功，其他平台需要自行测试可用性

## Usage

1. 下载项目 `ida-swift-demangle`
2. 如果是macOS只需要将ida_swift_demangle.py移动到:IDA Pro 7.0/ida.app/Contents/MacOS/plugins/下，如果是Windows需要移动所有文件
3. 打开IDA : 右键 -> DemangleSwift -> demangle swift of current functions 转换当前函数
4. 打开IDA : 右键 -> DemangleSwift -> demangle swift of all functions 转换所有函数

使用方法

![usage](./pic/usage.png)

使用前

![after](./pic/before.png)

使用后

![before](./pic/after.png)

## About

此项目大量借鉴了网上其他的脚本或者插件(下面会列出)
，修复了调用subprocess.Open会导致IDA插件假死或者闪退问题，并增加新功能支持右键选择运行(几行代码没有难度)，以下是参考项目，感谢大佬开源！

1. [tobefuturer/ida-swift-demangle](https://github.com/tobefuturer/ida-swift-demangle)
2. [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle)
3. [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch)
