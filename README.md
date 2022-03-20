# 华为电脑管家安装包启动器

该仓库用以解决华为电脑管家 V12 无法在非华为电脑上安装的问题。

## 使用方式

先安装 `Rust` 开发环境，这里就不赘述了。安装完环境后，克隆源码并构建：

```cmd
git clone https://github.com/hamflx/huawei-pc-manager-bootstrap.git
cd huawei-pc-manager-bootstrap
cargo +nightly-i686-pc-windows-msvc build --target=i686-pc-windows-msvc
```

构建成功后，将会在该目录 `target\i686-pc-windows-msvc\debug\program-bootstrap.exe` 中看到 `program-bootstrap.exe`。开启一个管理员（华为电脑管家安装需要管理员权限）命令行窗口，进入到该目录运行：

```cmd
program-bootstrap.exe PCManager_Setup_12.0.1.26(C233D003).exe
```
