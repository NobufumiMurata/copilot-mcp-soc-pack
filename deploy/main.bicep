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
      secrets: empty(apiKey) ? [] : [
        {
          name: 'api-key'
          value: apiKey
        }
      ]
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
          env: empty(apiKey) ? [] : [
            {
              name: 'MCP_SOC_PACK_API_KEY'
              secretRef: 'api-key'
            }
          ]
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
