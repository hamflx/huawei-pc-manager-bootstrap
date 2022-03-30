# 华为电脑管家安装包启动器

该仓库用以解决华为电脑管家 V12 无法在非华为电脑上安装的问题。

**声明：该仓库目前只解决了安装问题，安装后部分功能会无法使用或者不好用（基础的多屏协同可用但是交互会有些异常）。**

对于部分功能无法使用的问题，可以使用汉客儿网站的 `version.dll`（目前最新的是 `PCManagerMgrPatch.exe`）来解决，但是该工具是未开源的。

## 使用方式

先安装 `Rust` 开发环境，这里就不赘述了。安装完环境后，克隆源码并构建：

```cmd
git clone https://github.com/hamflx/huawei-pc-manager-bootstrap.git
cd huawei-pc-manager-bootstrap
cargo +nightly-i686-pc-windows-msvc build --target=i686-pc-windows-msvc
cargo +nightly-x86_64-pc-windows-msvc build --target=x86_64-pc-windows-msvc
```

构建成功后，将会在该目录 `target\i686-pc-windows-msvc\debug\program-bootstrap.exe` 中看到 `program-bootstrap.exe`。开启一个管理员（华为电脑管家安装需要管理员权限）命令行窗口，进入到该目录运行：

```cmd
program-bootstrap.exe PCManager_Setup_12.0.1.26(C233D003).exe
```
