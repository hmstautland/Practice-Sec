// Shared resources (deployed once into rg-seclab-shared-<region>): the container registry.
// Not compiled or deployed by the author - run `az bicep build` first. Check the current API versions.
targetScope = 'resourceGroup'

param location string = resourceGroup().location
param workload string = 'seclab'

var suffix = take(uniqueString(resourceGroup().id), 6)

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: 'acr${workload}${suffix}'
  location: location
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false            // no shared admin password; identities only (AcrPush for CI, AcrPull for apps)
    anonymousPullEnabled: false
    publicNetworkAccess: 'Enabled'     // CI on GitHub-hosted runners must reach it; see README for the Premium/private option
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
