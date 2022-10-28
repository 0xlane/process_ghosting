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

## 遗留问题

因为创建的进程属于无文件进程，在进程管理器里看着很怪异，暂时无法解决，不过单纯用来绕过静态进程文件扫描还是不错的。

![x](images/2022-10-28_16-06-08.png)
