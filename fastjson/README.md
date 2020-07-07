# fastjson 安全漏洞 {docsify-ignore}

?> 编辑：[@r4v3zn](https://github.com/0nise)

?> 漏洞作者：[@threedr3am](https://github.com/threedr3am)

Fastjson 是一个 Java 语言编写的高性能功能完善的 JSON 库。 它采用一种“假定有序快速匹配”的算法，把 JSON Parse 的性能提升到极致，是目前 Java 语言中最快的 JSON 库。 Fastjson 接口简单易用，已经被广泛使用在缓存序列化、协议交互、Web 输出、Android 客户端等多种应用场景。



| gadget                                                      | 影响版本           | 备注                     |
| ----------------------------------------------------------- | ------------------ | ------------------------ |
| Inet4Address<br/>Inet6Address<br/>InetSocketAddress<br/>URL | fastjson < 1.2.68  | 检测后端是否使用fastjson |
| HadoopHikari                                                | fastjson <= 1.2.68 | 需要开启 AutoType        |
| Shiro                                                       | fastjson <= 1.2.66 | 需要开启 AutoType        |
| JndiConverter                                               | fastjson <= 1.2.62 | 需要开启 AutoType        |
| IbatisSqlmap                                                | fastjson <= 1.2.62 | 需要开启 AutoType        |
| CocoonSlide                                                 | fastjson <= 1.2.62 | 需要开启 AutoType        |
| Anteros                                                     | fastjson <= 1.2.62 | 需要开启 AutoType        |
| CommonsProxy                                                | fastjson <= 1.2.61 | 需要开启 AutoType        |
| HikariConfig                                                | fastjson <= 1.2.59 | 需要开启 AutoType        |
| JdbcRowSetImpl                                              | fastjson <= 1.2.48 | 无需开启 AutoType        |
