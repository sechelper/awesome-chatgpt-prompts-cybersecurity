# awesome-chatgpt-prompts-cybersecurity
网络安全专拣训练指令集，让ChatGPT成为一名网络安全专家。

很多问题不是一个指令就可以得到精准结果的，需要根据每个问题深入去了解，不能浅尝即止，期待大家提交`prompts`。

最新指令发布在[助安社区](https://secself.com/)论坛，定期同步到此仓库。

## 渗透测试

### 历史漏洞跟踪，包括文章和POC脚本地址

> **提问**
>
> >Thinkphp有哪些漏洞，列出版本和cve编号，并给出漏洞文章和验证脚本地址。
>
> **回答：**
>
> > > ThinkPHP是一款基于PHP语言开发的Web应用框架，常见的漏洞有以下几种：
> > >
> > > 1. 命令执行（Command Injection）漏洞
> > >
> > >   - 版本：Thinkphp 5.0.0-5.0.22、5.1.0-5.1.31
> > >   - CVE编号：CVE-2018-13163
> > >   - 漏洞文章：[ThinkPHP框架命令执行漏洞分析(CVE-2018-13163)](https://www.freebuf.com/vuls/181983.html)
> > >   - 验证脚本：[thinkphp_rce.py](https://github.com/5ecurity0ps/CVE-2018-13163)
> > >
> > > 2. SQL注入漏洞
> > >
> > >   - 版本：Thinkphp 3.x、5.x
> > >   - CVE编号：CVE-2018-20062
> > >   - 漏洞文章：[深入剖析ThinkPHP框架之SQL注入](https://xz.aliyun.com/t/3569)
> > >   - 验证脚本：[thinkphp-sqli-exploit.py](https://github.com/0xkami/thinkphp-sqli-exploit)
> > >
> > > 3. 文件包含漏洞
> > >
> > >   - 版本：Thinkphp 3.x和5.x
> > >   - CVE编号：CVE-2018-19409
> > >   - 漏洞文章：[ThinkPHP v5.0.23 / v5.1.31 远程代码执行漏洞 (CVE-2018-19409) 分析报告](https://mp.weixin.qq.com/s/5I8nM_tZ6jKw3zPQlU2rbA)
> > >   - 验证脚本：[thinkphp_vul_exploit.py](https://github.com/vulhub/vulhub/tree/master/thinkphp/CVE-2018-19409)
> > >
> > > 4. 文件上传漏洞
> > >
> > >   - 版本：ThinkPHP 5.x
> > >   - CVE编号：CVE-2019-9082
> > >   - 漏洞文章：[漏洞预警 | ThinkPHP框架文件上传漏洞](https://www.freebuf.com/vuls/198573.html)
> > >   - 验证脚本：[thinkphp_file_uploader.py](https://github.com/CaledoniaProject/thinkphp_file_uploader)
> > >
> > > 以上是ThinkPHP常见的漏洞和相关信息，建议开发者在使用过程中及时更新版本，并对开发代码进行安全审查。同时也需要注意服务器防火墙、WAF等相关安全措施的部署和配置。

### 工具推荐

> **提问**
>
> > 推荐四款开源子域名枚举工具给出相应地址，按照使用人数排序。
> >
> >  **回答**
> > > 以下是按照使用人数排序的四款开源子域名枚举工具及其相应地址：
> > >
> > > 1. **Sublist3r**：通过搜索公共资源，例如搜索引擎、DNS历史记录和在线证书透明度等来枚举子域名。它支持多个搜索引擎以及自定义搜索引擎，并且可以通过API导入结果。Sublist3r基于Python编写，兼容Linux和Windows系统。地址为：https://github.com/aboul3la/Sublist3r
> > > 2. **Amass**：一款功能强大的子域名枚举工具，可由Active Reconnaissance技术和公共资源数据来源生成子域名列表。Amass能够从各种不同的来源获取数据，包括互联网地址空间、域名注册信息、DNS服务器和网络地图，它还提供了一个Web界面用于交互式操作。Amass基于Go语言编写，跨平台运行。地址为：https://github.com/OWASP/Amass
> > > 3. **Subfinder**：一款快速而轻巧的子域枚举工具，它利用各种不同的源来发现子域名。Subfinder集成了许多常用的子域名源，但也允许添加自定义源。Subfinder基于Golang编写，跨平台兼容性良好。地址为：https://github.com/projectdiscovery/subfinder
> > > 4. **Knockpy**：使用Python编写的子域名枚举工具，它可以快速地发现目标网站的所有子域名。Knockpy充分利用了搜索引擎和在线API来查找子域名，同时还具有自定义模块和过滤器功能。Knockpy易于安装和使用，并支持批量检测。地址为：https://github.com/guelfoweb/knock

### 工具使用

> **提问**
>
> > 举例讲解Knockpy尽可能多的使用方法。
> >
> > **回答**
> > > Knockpy是一款用于扫描多个主机以发现相同端口的工具，可以用于识别网络上隐藏的服务。以下是Knockpy的使用方法：
> > >
> > > 1. 安装Knockpy
> > >
> > > 首先需要安装Knockpy，可以在终端中运行以下命令来安装：
> > >
> > > ```
> > > 
> > > pip install knockpy
> > > ```
> > >
> > > 2. 基本使用方法
> > >
> > > 运行Knockpy时需要至少提供一个目标主机地址或IP地址范围。以下是基本的使用方法：
> > >
> > > ```
> > > 
> > > knockpy domain.com
> > > ```
> > >
> > > 这将扫描目标域名下的所有常见端口，并输出其状态。
> > >
> > > 3. 指定端口列表
> > >
> > > 如果只想扫描特定的端口，可以使用“-p”参数并指定要扫描的端口列表。例如：
> > >
> > > ```
> > > 
> > > knockpy domain.com -p 22,80,443
> > > ```
> > >
> > > 这将只扫描22、80和443端口，并输出其状态。
> > >
> > > 4. 导出结果
> > >
> > > 可以使用“-w”参数将扫描结果导出为文本文件，例如：
> > >
> > > ```
> > > 
> > > knockpy domain.com -w results.txt
> > > ```
> > >
> > > 这将把结果保存在名为results.txt的文件中。
> > >
> > > 5. 忽略DNS解析
> > >
> > > 默认情况下，Knockpy会尝试对目标进行DNS解析，但有时可能不需要这样做。可以使用“--no-resolve”参数来禁用DNS解析。
> > >
> > > 6. 使用代理服务器
> > >
> > > 如果需要通过代理服务器扫描目标，可以使用“-x”参数并指定代理服务器的地址和端口号。例如：
> > >
> > > ```
> > > 
> > > knockpy domain.com -x http://192.168.1.100:8080
> > > ```
> > >
> > > 这将通过地址为192.168.1.100，端口为8080的HTTP代理服务器扫描目标。
> > >
> > > 7. 使用自定义配置文件
> > >
> > > Knockpy也支持使用自定义配置文件，其中包含要扫描的端口列表、代理服务器等信息。可以使用“-c”参数并指定配置文件路径。例如：
> > >
> > > ```
> > > 
> > > knockpy domain.com -c /path/to/config.ini
> > > ```
> > >
> > > 以上就是Knockpy的举例讲解，希望对您有所帮助。


## 代码审计

> **提问**
>
> > 你现在是代码安全审计专家，接下来的对话我发送的是代码，审计代码并生成报告，审计报告应该包括：代码功能、不安全代码位置和原理、修复建议、代码补丁。
> >
> > **回答**
> >
> > > 好的，我将审计您提供的代码，并生成相应的报告。请提供要审计的代码。
> > >
>
> **提问**
>
> > ```
> > package main
> > 
> > import (
> > 	"context"
> > 	"github.com/gin-gonic/gin"
> > 	"go.mongodb.org/mongo-driver/mongo"
> > 	"go.mongodb.org/mongo-driver/mongo/options"
> > 	"os/exec"
> > )
> > 
> > func Execute(c *gin.Context) {
> > 	cmd, _ := c.GetPostForm("cmd")
> > 	exec.Command(cmd)
> > }
> > 
> > func main() {
> > 	// 创建MongoDB客户端
> > 	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://192.168.111.133:27017"))
> > 	if err != nil {
> > 		panic(err)
> > 	}
> > 	err = client.Connect(context.Background())
> > 	if err != nil {
> > 		panic(err)
> > 	}
> > 
> > 	// 创建Gin路由
> > 	router := gin.Default()
> > 
> > 	// banners 上传，统一格式存储
> > 	router.POST("/api/v1/upload-banners", Execute)
> > 
> > 	// 启动HTTP服务器
> > 	router.Run("127.0.0.1:8080")
> > 
> > }
> > ```
> >
> > **回答**
> >
> > > 经过审计，以下是该代码的报告：
> > >
> > > ## 代码功能
> > >
> > > 此代码是一个HTTP服务器，使用Gin框架提供API接口。其中包括一个 `/api/v1/upload-banners` 接口，该接口执行用户提交的命令。
> > >
> > > ## 不安全的代码位置和原理
> > >
> > > 在函数 `Execute()` 中，代码从HTTP请求参数中获取命令并直接执行。这个设计存在一定的安全隐患，因为攻击者可以通过构造恶意请求来执行任意系统命令，导致服务器被入侵、数据泄露等安全问题。
> > >
> > > ## 修复建议
> > >
> > > 为了确保服务器的安全性，应该避免在代码中直接执行用户输入的命令。在处理用户输入时，必须对输入进行严格的验证和过滤，同时采用最小权限原则运行程序。
> > >
> > > 修复措施：
> > >
> > > - 对于命令执行函数 `Execute()`，应该检查输入的命令是否合法，例如只允许某些特定的命令，并且不允许用户输入任何参数。
> > > - 使用 Go 标准库中的 os/exec 包来执行命令，而不是直接调用系统命令。
> > >
> > > 正确的代码如下所示：
> > >
> > > ```
> > > go
> > > func Execute(c *gin.Context) {
> > >     cmd := c.PostForm("cmd")
> > >     if cmd == "" {
> > >         c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid command"})
> > >         return
> > >     }
> > > 
> > >     // 只允许执行 echo 命令
> > >     if cmd != "echo" {
> > >         c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "command not allowed"})
> > >         return
> > >     }
> > > 
> > >     // 执行命
> > > ...
> > > ```

### 提升工作效率，生成思维导图

> **提问**
>
> > 逆向工程零基础入门，回答结果要求符合导入xmind思维导图的标准
> >
> > **回答**
> >
> > > # Python网络安全编程零基础入门
> > >
> > > ## 网络安全基础
> > >
> > > ### 1. 网络协议
> > >
> > > - OSI七层模型
> > > - TCP/IP协议族
> > > - HTTP协议
> > > - HTTPS协议
> > > - DNS协议
> > >
> > > ### 2. 网络攻击
> > >
> > > - DoS/DDoS攻击
> > > - SQL注入攻击
> > > - XSS攻击
> > > - CSRF攻击
> > > - 暴力破解攻击
> > > - 社会工程学攻击
> > >
> > > ### 3. 网络防御
> > >
> > > - 防火墙
> > > - IDS/IPS
> > > - WAF
> > > - VPN
> > > - 安全加固
> > >
> > > ## Python网络编程
> > >
> > > ### 1. Socket编程
> > >
> > > - TCP Socket编程
> > > - UDP Socket编程
> > >
> > > ### 2. Scapy库
> > >
> > > - Scapy简介
> > > - Scapy的使用
> > >
> > > ### 3. 爬虫框架
> > >
> > > - Requests库
> > > - BeautifulSoup库
> > > - Scrapy框架
> > >
> > > ### 4. 加密与解密
> > >
> > > - 对称加密
> > > - 非对称加密
> > > - Hash算法
> > >
> > > ## Python网络安全编程
> > >
> > > ### 1. 渗透测试
> > >
> > > - 渗透测试方法论
> > > - 渗透测试工具
> > >
> > > ### 2. 漏洞挖掘
> > >
> > > - 漏洞挖掘思路
> > > - 漏洞挖掘工具
> > >
> > > ### 3. Web安全
> > >
> > > - Web漏洞分类
> > > - Web漏洞利用
> > > - Web安全加固
> > >
> > > ### 4. 网络安全编程实战
> > >
> > > - DDos攻击检测
> > > - 邮件伪造检测
> > > - 端口扫描与弱口令爆破检测
>
> 导出的文件[渗透信息收集结构.xmind](resources/渗透信息收集结构.xmind)