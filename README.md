# Blurr

把一段文字或一个文件加密成只含 ASCII 字母、数字、普通空格的文本文件，使用相同 key 解密还原。支持中文和任意文件编码。

## 安装与运行

需要 Python 3.11 或更新版本及 [uv](https://docs.astral.sh/uv/)。

```sh
cd /Users/ericliu/Code/projects/Blurr
uv sync
uv run blurr --help
```

可选：`uv tool install .` 安装为独立的 `blurr` 命令。也支持 `uv run python -m blurr`。

## 加密与解密

加密文字，默认 UTF-8。省略 key 参数时会隐藏输入，并在加密时要求确认：

```sh
uv run blurr encrypt --text '你好，世界！Hello 🌏' -o secret.txt
uv run blurr decrypt -i secret.txt -o restored.txt
```

加密文件时不需要指定编码，解密后逐字节还原，包括 GBK、GB18030、Big5、UTF-8、UTF-16、BOM、CRLF 等。输出文件名不会影响编码：

```sh
uv run blurr encrypt -i original.txt -o secret.txt
uv run blurr decrypt -i secret.txt -o restored.txt
```

如果输入的是命令行文字，希望解密结果使用 GB18030 编码：

```sh
uv run blurr encrypt --text '中文内容' --encoding gb18030 -o secret.txt
uv run blurr decrypt -i secret.txt -o restored-gb18030.txt
```

`--encoding` 只用于 `encrypt --text`；文件输入保持原始字节，解密不转码。文字无法用指定编码表达时会报错。

自动化可用 `--key-env NAME` 读取已有环境变量；也支持 `--key '你的口令'`，但命令参数可能出现在 shell 历史或进程列表中。不要把真实 key 写进脚本或版本库。

```sh
# 先在环境中设置 BLURR_KEY，然后运行：
uv run blurr encrypt -t '中文内容' --key-env BLURR_KEY -o secret.txt
uv run blurr decrypt -i secret.txt --key-env BLURR_KEY -o restored.txt

# 从标准输入读取原始字节；管道模式需要显式提供 key 或 key 环境变量
printf '中文内容' | uv run blurr encrypt -i - --key-env BLURR_KEY -o secret.txt
```

解密也支持 `--text 'Blurr1 ...'` 直接传入密文，或 `-i -` 从标准输入读取密文。

默认拒绝覆盖已有输出文件；确需覆盖时传 `--force`。输入和输出不能指向同一文件，即使使用 `--force` 也会拒绝。输出始终是文件，成功不打印内容；失败返回非零状态并向 stderr 报错。

## 加密与文本格式

- key 是秘密口令，支持中文；空 key 被拒绝。大小写、空格和 Unicode 表示形式均有意义，不会自动归一化。
- 每次生成随机 16 字节 salt 和 12 字节 nonce；salt 随密文存储，解密只需相同 key。
- Scrypt 从 key 的 UTF-8 字节派生 32 字节密钥，v1 固定参数 `N=131072, r=8, p=1`，约需要 128 MiB KDF 内存。
- 使用 `cryptography` 的 AES-256-GCM 和完整 16 字节认证标签。错误 key、密文损坏或篡改会导致解密失败，验证完成前不写入任何明文。
- 二进制负载采用标准 Base32 编码，去掉 `=` 填充符，每 16 字符用普通空格分组，添加 `Blurr1 ` 前缀。因此实际使用的字符是所允许集合的子集；不会出现标点、制表符、BOM 或换行，文件末尾也没有换行。
- 密文主体约为原始字节的 1.7 倍，另有前缀及固定开销。空文件也可加密。
- 输出通过同目录临时文件原子发布；POSIX 系统上权限为 `0600`。验证失败时不会创建或覆盖输出文件，`--force` 下同样如此。

v1 格式如下，整数参数固定在协议内，不能在原版本中修改：

```text
Blurr1 BASE32WITHOUTPADDING
payload = salt[16] || nonce[12] || ciphertext || GCM tag[16]
AAD = ASCII("Blurr1 AES256GCM Scrypt N131072 r8 p1")
```

解码接受普通空格重新分组，但拒绝其他字符，包括 CR/LF。主体 Base32 大小写敏感，并校验无填充编码的规范形式。前缀决定算法版本，认证附加数据绑定该版本及算法参数。

实现依据：[AES-GCM 文档](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)、[Scrypt 文档](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt)。

请保管好 key；丢失后无法恢复。当前版本把整个文件读入内存，适合文字和普通文本文件；尚未实现大文件流式加密，也不会隐藏原文长度。不保存文件名、文件权限或时间戳，只还原内容。

## Python API

```python
from blurr import decrypt, encrypt

ciphertext = encrypt('你好'.encode('utf-8'), key='示例口令')
original = decrypt(ciphertext, key='示例口令')  # bytes
assert original.decode('utf-8') == '你好'
```

## 开发与验证

```sh
uv sync
uv run pytest -q
uv build
```

源码位于 `src/blurr/`。测试覆盖多编码、空文件、随机性、错误 key、篡改检测、格式约束、命令行输入、原文件保护和输出失败清理。
