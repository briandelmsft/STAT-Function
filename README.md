# STAT-Function

This function is part of the Microsoft Sentinel Triage AssistanT project.  For more information and deployment instructions visit https://aka.ms/mstat

## Debug Info

To debug in VS Code create a local.settings.json file in the root of the project

```
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_TENANT_ID": "<TENANTID>",
    "AZURE_CLIENT_ID": "<CLIENTID>",
    "AZURE_CLIENT_SECRET": "<SECRET>",
    "AZURE_AUTHORITY_HOST": "login.microsoftonline.com",
    "ARM_ENDPOINT": "management.azure.com",
    "GRAPH_ENDPOINT": "graph.microsoft.com",
    "LOGANALYTICS_ENDPOINT": "api.loganalytics.io",
    "M365_ENDPOINT": "api.security.microsoft.com",
    "MDE_ENDPOINT": "api.securitycenter.microsoft.com"
  }
}
```
