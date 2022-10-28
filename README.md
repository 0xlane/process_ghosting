# Process Ghosting

这个是根据 [hasherezade/process_ghosting](https://github.com/hasherezade/process_ghosting) 项目改的 rust 版本代码。

## 编译方法

```bash
cargo build
```

## 使用方法

```bash
process_ghosting.exe <target_path> <payload_path>
```

![x](./screenshot.png)

## 技术原理

参考：[https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)

大致利用步骤：

1. 创建一个文件，需具有 DELETE 权限
2. 调用 NtSetInformationFile 将 FILE_DISPOSITION_INFO 的 DeleteFile 设置为 TRUE
3. 写恶意内容到该文件中，由于该文件当前是 delete-pending 状态，外部无法打开此文件
4. 用这个文件创建一个 IMAGE 内存段
5. 关闭文件句柄，该文件会被自动删除
6. 使用 IMAGE 段创建进程，该进程磁盘上无文件对应
7. 设置进程参数和环境变量信息
8. 为这个进程创建一个线程执行恶意内容

在最后一步的时候，会触发进程创建内核回调，进程在磁盘上无文件与之对应，可让一些静态检测引擎失效。

该技术除了使用 delete_on_close 文件自删除机制之外，还需配合进程命令行参数伪造技术一起使用。

## 遗留问题

因为创建的进程属于无文件进程，在进程管理器里看着很怪异，暂时无法解决，不过单纯用来绕过静态进程文件扫描还是不错的。

![x](images/2022-10-28_16-06-08.png)
