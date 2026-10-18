package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Windows Server RDL Service open(CVE-2024-38077)",
    "Description": "<p>Windows Server Remote Desktop Licensing Service (RDL) is a feature provided by Microsoft that manages and distributes client access licenses for Remote Desktop Services. It ensures that only users or devices with valid licenses can access the remote desktop environment. </p><p>According to the rules, we detect the existence of the Windows Server Remote Desktop Authorization Service (RDL), and the Windows Server server on which the service is enabled may have the CVE-2024-38077 vulnerability.</p>",
    "Product": "Windows-server",
    "Homepage": "https://www.microsoft.com/",
    "DisclosureDate": "2024-07-09",
    "PostTime": "2024-08-23",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "banner=\"3d267954-eeb7-11d1-b94e-00c04fa3080d\" && protocol=\"dcerpc\"",
    "GobyQuery": "banner=\"3d267954-eeb7-11d1-b94e-00c04fa3080d\" && protocol=\"dcerpc\"",
    "Level": "0",
    "Impact": "<p>Attackers can directly gain the highest privileges on the server and execute arbitrary operations without any prerequisites or user interaction (zero-click).</p>",
    "Recommendation": "<p>1. Update and install the July system patch, for the system that cannot automatically update the patch, please refer to <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077.\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077.</a>  </p><p>2. Disable the remote desktop authorization service. The service is not enabled by default.  </p><p>3. In order to prevent exploitation, it is recommended to minimize direct exposure of ports to the outside world, and use security groups to restrict relevant machines and ports from being open only to trusted addresses.</p>",
    "References": [
        "https://github.com/SecStarBot/CVE-2024-38077-POC"
    ],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
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
        "HW-2024"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2024-38077,CVE-2024-38076"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "2.0",
    "Translation": {
        "CN": {
            "Name": "Windows Server RDL 服务开放（CVE-2024-38077）",
            "Product": "Windows-server",
            "Description": "<p>Windows Server 远程桌面授权服务（RDL）是微软提供的一项功能，用于管理和分发远程桌面服务的客户端访问许可。它确保只有拥有有效许可的用户或设备可以访问远程桌面环境。<br></p><p>根据规则我们探测出Windows Server 远程桌面授权服务（RDL）的存在，开启该服务的Windows Server服务器可能存在CVE-2024-38077漏洞。</p>",
            "Recommendation": "<p>1、更新安装7月系统补丁，针对无法自动更新补丁的系统，可参考 <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077</a> 。&nbsp;</p><p>2、关闭远程桌面授权服务。该服务默认情况下并未开启。&nbsp;</p><p>3、为防止被利用，建议尽量减少对外直接暴露端口，可利用安全组限制相关机器以及端口仅对可信地址开放。<br></p>",
            "Impact": "<p>攻击者无需任何前置条件，无需用户交互（零点击）便可直接获取服务器最高权限，执行任意操作。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Windows Server RDL Service open(CVE-2024-38077)",
            "Product": "Windows-server",
            "Description": "<p>Windows Server Remote Desktop Licensing Service (RDL) is a feature provided by Microsoft that manages and distributes client access licenses for Remote Desktop Services. It ensures that only users or devices with valid licenses can access the remote desktop environment.&nbsp;</p><p>According to the rules, we detect the existence of the Windows Server Remote Desktop Authorization Service (RDL), and the Windows Server server on which the service is enabled may have the CVE-2024-38077 vulnerability.<br></p>",
            "Recommendation": "<p>1. Update and install the July system patch, for the system that cannot automatically update the patch, please refer to <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077.\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077.</a>&nbsp;&nbsp;</p><p>2. Disable the remote desktop authorization service. The service is not enabled by default.&nbsp;&nbsp;</p><p>3. In order to prevent exploitation, it is recommended to minimize direct exposure of ports to the outside world, and use security groups to restrict relevant machines and ports from being open only to trusted addresses.<br></p>",
            "Impact": "<p>Attackers can directly gain the highest privileges on the server and execute arbitrary operations without any prerequisites or user interaction (zero-click).</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "HW-2024"
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
    "Variables": {},
    "PocId": "9943"
}`
	tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024 := func(hexData string, conn net.Conn, flag string) (string, error) {
		data, err := hex.DecodeString(hexData)
		if err != nil {
			return "", err
		}
		_, err = conn.Write(data)
		if err != nil {
			return "", err
		}
		// 根据flag 决定对返回包的处理
		if flag == "TargetPort" {
			buffer1 := make([]byte, 1024)
			_, err = conn.Read(buffer1)
			// 接收到响应，截取攻击ip的对应漏洞端口
			vulPortHex := fmt.Sprintf("%x", buffer1[136:138])
			vulPort, err := strconv.ParseUint(vulPortHex, 16, 32)
			if err != nil {
				return "", err
			}
			return strconv.FormatUint(vulPort, 10), nil
		} else if flag == "default" {
			// 默认进行数据读取
			buffer2 := make([]byte, 4096)
			_, err = conn.Read(buffer2)
			if err != nil {
				return "", err
			}
			return "Success", nil
		} else if flag == "check" {
			buffer3 := make([]byte, 1024)
			n, err := conn.Read(buffer3)
			if err != nil {
				// 从连接中读取数据错误
				return "", nil
			}
			// 输出实际读取的字节数，48为存在漏洞，32为已打补丁
			if n == 48 {
				return "vulnerabilities", nil
			} else {
				return "Success", nil
			}
		}
		// 接收返回,第四次请求不接收返回,无错误默认返回Success
		return "Success", nil

	}
	tcpHttpConnection5362341380772024 := func(hostInfo *httpclient.FixUrl) (string, error) {
		respTxt := ""
		serverAddr := hostInfo.HostInfo
		// 建立 TCP 连接
		conn, err := httpclient.GetTCPConn(serverAddr)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		// 设置读写超时时间为10秒
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		// 16 进制数据,第一次连接请求
		hexData := "05000b03100000004800000001000000b810b8100000000001000000000001000883afe11f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe808002b10486002000000"
		data, err := tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024(hexData, conn, "default")
		if err != nil {
			return "", err
		}
		//第一次连接第二次请求,获取第二次连接的端口
		hexData = "05000003100000009c0000000100000084000000000003000100000000000000000000000000000000000000020000004b0000004b000000050013000d5479263db7eed111b94e00c04fa3080d01000200000013000d045d888aeb1cc9119fe808002b10486002000200000001000b0200000001000702000000010009040000000000ab000000000000000000000000000000000000000001000000"
		data, err = tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024(hexData, conn, "TargetPort")
		if err != nil {
			return "", err
		}
		//替换serverAddr端口进行第二次连接
		newServerAddr := strings.ReplaceAll(serverAddr, "135", data)
		conn2, err := httpclient.GetTCPConn(newServerAddr)
		if err != nil {
			return "", err
		}
		defer conn2.Close()
		// 第三次请求
		conn2.SetDeadline(time.Now().Add(10 * time.Second))
		hexData = "05000b03100000007000200001000000b810b8100000000001000000000001005479263db7eed111b94e00c04fa3080d01000000045d888aeb1cc9119fe808002b104860020000000a0200007f3501004e544c4d5353500001000000358288e000000000000000000000000000000000"
		data, err = tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024(hexData, conn2, "default")
		if err != nil {
			return "", err
		}
		// 第四次请求 无buffer返回，设置flag为"",不设置会等待返回信息
		hexData = "05001003100000006d00510001000000202020200a0200007f3501004e544c4d5353500003000000010001004000000000000000410000000000000040000000000000004000000000000000400000001000100041000000358288e0009c71dd29926f046afe6b752d2f28d63f"
		data, err = tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024(hexData, conn2, "")
		if err != nil {
			return "", err
		}
		// 第五次请求 最终判断,通过返回长度为指定长度进行判断
		hexData = "050000031000000018000000020000000000000000000100"
		respTxt, err = tcpRequest_cvhjsdhujyfghvsdyhQWEDSADSdsdfdsd380772024(hexData, conn2, "check")
		if err != nil {
			return "", err
		}
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//非HTTP数据包没有路径
			vulURL := ""
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			// 函数继承
			tcpConnection := tcpHttpConnection5362341380772024
			resp, err := tcpConnection(u)

			if err != nil {
				return false
			}
			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			// 如果第五次发包返回vulnerabilities则代表存在漏洞
			if strings.Contains(resp, "vulnerabilities") {
				// 设置VULURL
				ss.VulURL = u.HostInfo + vulURL
				return true
			}
			return false
		},
		nil,
	))
}
