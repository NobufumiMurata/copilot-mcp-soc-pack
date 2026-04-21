// Copilot MCP SOC Pack — Azure Container Apps deployment.
//
// Deploys:
//   - Log Analytics workspace (Pay-As-You-Go)
//   - Container Apps Environment (Consumption)
//   - Container App (scale-to-zero, HTTPS ingress, optional API-key secret)
//
// Parameters let a SOC team pick the image tag, container name, and an API key.

targetScope = 'resourceGroup'

@description('Name for the Container App. Also used as a prefix for the environment and Log Analytics workspace.')
@minLength(3)
@maxLength(24)
param containerAppName string = 'copilot-mcp-soc-pack'

@description('Azure region for the deployment. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Container image. Use the published image or point to your own fork.')
param image string = 'ghcr.io/nobufumimurata/copilot-mcp-soc-pack:latest'

@description('Shared API key that Security Copilot and MCP clients must send in the X-API-Key header. Leave empty to disable auth (development only).')
@secure()
param apiKey string = ''
@description('Free abuse.ch Auth-Key (https://auth.abuse.ch/). Required for the /abusech/* endpoints (MalwareBazaar, ThreatFox, URLhaus). Leave empty to disable those endpoints.')
@secure()
param abuseChAuthKey string = ''
@description('Free GreyNoise Community API key (https://viz.greynoise.io/signup). Required for /greynoise/classify. Leave empty to disable.')
@secure()
param greynoiseApiKey string = ''
@description('Free AbuseIPDB API key (https://www.abuseipdb.com/register). Required for /abuseipdb/check. Leave empty to disable.')
@secure()
param abuseIpdbApiKey string = ''
@description('Free AlienVault OTX API key (https://otx.alienvault.com/, Settings -> API Integration). Required for /otx/* endpoints. Leave empty to disable.')
@secure()
param otxApiKey string = ''
@description('Provision a workspace-based Application Insights resource and inject APPLICATIONINSIGHTS_CONNECTION_STRING into the container. Requires the image to ship the optional `tracing` extra (default image does).')
param enableAppInsights bool = false
@description('Minimum number of replicas. Set 0 for scale-to-zero.')
@minValue(0)
@maxValue(5)
param minReplicas int = 0

@description('Maximum number of replicas.')
@minValue(1)
@maxValue(30)
param maxReplicas int = 3

var logAnalyticsName = '${containerAppName}-logs'
var environmentName = '${containerAppName}-env'
var appInsightsName = '${containerAppName}-ai'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = if (enableAppInsights) {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      secrets: concat(
        empty(apiKey) ? [] : [
          {
            name: 'api-key'
            value: apiKey
          }
        ],
        empty(abuseChAuthKey) ? [] : [
          {
            name: 'abusech-auth-key'
            value: abuseChAuthKey
          }
        ],
        empty(greynoiseApiKey) ? [] : [
          {
            name: 'greynoise-api-key'
            value: greynoiseApiKey
          }
        ],
        empty(abuseIpdbApiKey) ? [] : [
          {
            name: 'abuseipdb-api-key'
            value: abuseIpdbApiKey
          }
        ],
        empty(otxApiKey) ? [] : [
          {
            name: 'otx-api-key'
            value: otxApiKey
          }
        ],
        enableAppInsights ? [
          {
            name: 'applicationinsights-connection-string'
            value: appInsights!.properties.ConnectionString
          }
        ] : []
      )
    }
    template: {
      containers: [
        {
          name: 'app'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: concat(
            empty(apiKey) ? [] : [
              {
                name: 'MCP_SOC_PACK_API_KEY'
                secretRef: 'api-key'
              }
            ],
            empty(abuseChAuthKey) ? [] : [
              {
                name: 'ABUSE_CH_AUTH_KEY'
                secretRef: 'abusech-auth-key'
              }
            ],
            empty(greynoiseApiKey) ? [] : [
              {
                name: 'GREYNOISE_API_KEY'
                secretRef: 'greynoise-api-key'
              }
            ],
            empty(abuseIpdbApiKey) ? [] : [
              {
                name: 'ABUSEIPDB_API_KEY'
                secretRef: 'abuseipdb-api-key'
              }
            ],
            empty(otxApiKey) ? [] : [
              {
                name: 'OTX_API_KEY'
                secretRef: 'otx-api-key'
              }
            ],
            enableAppInsights ? [
              {
                name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
                secretRef: 'applicationinsights-connection-string'
              }
              {
                name: 'OTEL_SERVICE_NAME'
                value: containerAppName
              }
            ] : [],
            // Public base URL injected into the OpenAPI `servers[]` block.
            // Required for Microsoft Security Copilot's Agent Builder
            // API Tool importer to resolve operation base URLs (the
            // legacy Custom plugin path uses the manifest's EndpointUrl
            // instead and works without this).
            [
              {
                name: 'MCP_SOC_PACK_PUBLIC_BASE_URL'
                value: 'https://${containerAppName}.${environment.properties.defaultDomain}'
              }
            ]
          )
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 5
              periodSeconds: 15
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}

output fqdn string = containerApp.properties.configuration.ingress.fqdn
output endpoint string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output openApiUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}/openapi.json'
output mcpSseUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}/mcp/'
output appInsightsName string = enableAppInsights ? appInsights!.name : ''
