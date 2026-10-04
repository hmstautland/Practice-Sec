// Reference solution for P2-04: one SecLab environment in one resource group.
// STATUS: written without access to an Azure subscription or the Bicep CLI. NOT compiled, NOT deployed.
// Run `az bicep build` / `az bicep lint` / `what-if` and fix API-version or property drift before use.
targetScope = 'resourceGroup'

// ---------- parameters: none of them is a secret ----------
@allowed(['dev', 'test', 'prod'])
param env string
param location string = resourceGroup().location
param workload string = 'seclab'

@description('Image references by digest, e.g. acrseclabab12cd.azurecr.io/seclab-api@sha256:...')
param apiImage string
param externalApiImage string

@description('Shared registry (deployed with shared.bicep) and its resource group')
param acrName string
param acrResourceGroup string

@description('Entra group that administers the SQL server (Entra-only auth). Members run migrations / create DB users.')
param sqlAdminGroupObjectId string
param sqlAdminGroupName string

param alertEmail string
param addressPrefix string = '10.20.0.0/16'
param staticSiteLocation string = 'westeurope'
@description('Front Door profile id of THIS environment, passed back in after the first deployment (empty on first run).')
param frontDoorId string = ''
@description('Optional custom domain for the API edge, e.g. api.dev.example.com (DNS validation is a manual step).')
param apiCustomDomain string = ''
@allowed(['Detection', 'Prevention'])
param wafMode string = 'Prevention'

var isProd = env == 'prod'
var suffix = take(uniqueString(resourceGroup().id), 6)
var base = '${workload}-${env}'
var tenantId = subscription().tenantId

// Built-in role definition ids (verify with `az role definition list --name "<role>"`)
var roles = {
  kvSecretsUser: '4633458b-17de-408a-b874-0f8bf1c7c9d4'
  kvCryptoUser: '12338af0-0e69-4776-bea7-57ae8d297424'
  blobContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
}

// ---------- monitoring ----------
resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${base}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: isProd ? 90 : 30
    features: { disableLocalAuth: false }
  }
}

resource appi 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${base}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: law.id
    DisableLocalAuth: true     // ingestion needs Entra auth: the exporter uses the managed identity
  }
}

// ---------- identity ----------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${base}'
  location: location
}

module acrPull 'acr-pull.bicep' = {
  name: 'acr-pull-${env}'
  scope: resourceGroup(acrResourceGroup)
  params: { acrName: acrName, principalId: uami.properties.principalId }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
  scope: resourceGroup(acrResourceGroup)
}

// ---------- network ----------
resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: 'vnet-${base}'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [addressPrefix] }
    subnets: [
      {
        name: 'snet-aca'
        properties: {
          addressPrefix: cidrSubnet(addressPrefix, 23, 0)
          delegations: [{ name: 'aca', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
      {
        name: 'snet-pe'
        properties: { addressPrefix: cidrSubnet(addressPrefix, 24, 2) }
      }
    ]
  }
}

// ---------- key vault ----------
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${base}-${suffix}'
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true          // cannot be switched off later
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource dpKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: kv
  name: 'dataprotection'
  properties: {
    kty: 'RSA'
    keySize: 2048
    keyOps: ['wrapKey', 'unwrapKey']
  }
}

// ---------- storage for the Data Protection key ring ----------
resource st 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: toLower('st${workload}${env}${suffix}')
  location: location
  kind: 'StorageV2'
  sku: { name: isProd ? 'Standard_ZRS' : 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false          // Entra only
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource blobSvc 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: st
  name: 'default'
}

resource dpContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobSvc
  name: 'dataprotection'
  properties: { publicAccess: 'None' }
}

// ---------- azure sql ----------
resource sql 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: 'sql-${base}-${suffix}'
  location: location
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
    restrictOutboundNetworkAccess: 'Disabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'Group'
      login: sqlAdminGroupName
      sid: sqlAdminGroupObjectId
      tenantId: tenantId
      azureADOnlyAuthentication: true     // no SQL logins, no sa-style password exists
    }
  }
}

resource db 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sql
  name: 'SecLab'
  location: location
  sku: isProd
    ? { name: 'GP_Gen5_2', tier: 'GeneralPurpose' }
    : { name: 'GP_S_Gen5_1', tier: 'GeneralPurpose' }
  properties: {
    requestedBackupStorageRedundancy: isProd ? 'Geo' : 'Local'
    autoPauseDelay: isProd ? -1 : 60
    minCapacity: isProd ? null : json('0.5')
  }
}

resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-08-01-preview' = {
  parent: db
  name: 'current'
  properties: { state: 'Enabled' }
}

resource sqlAudit 'Microsoft.Sql/servers/auditingSettings@2023-08-01-preview' = {
  parent: sql
  name: 'default'
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true    // needs the diagnostic setting on `master` below
  }
}

resource sqlThreat 'Microsoft.Sql/servers/securityAlertPolicies@2023-08-01-preview' = {
  parent: sql
  name: 'Default'
  properties: { state: 'Enabled' }       // Defender for SQL threat detection; the subscription-level Defender plan is enabled separately
}

resource sqlMaster 'Microsoft.Sql/servers/databases@2023-08-01-preview' existing = {
  parent: sql
  name: 'master'
}

resource sqlMasterDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: sqlMaster
  properties: {
    workspaceId: law.id
    logs: [{ category: 'SQLSecurityAuditEvents', enabled: true }]
  }
}

// ---------- private endpoints + private DNS (sql, key vault, blob) ----------
var privateLinks = [
  { key: 'sql', targetId: sql.id, groupId: 'sqlServer', zone: 'privatelink${environment().suffixes.sqlServerHostname}' }
  { key: 'kv', targetId: kv.id, groupId: 'vault', zone: 'privatelink.vaultcore.azure.net' }
  { key: 'blob', targetId: st.id, groupId: 'blob', zone: 'privatelink.blob.${environment().suffixes.storage}' }
]

resource zones 'Microsoft.Network/privateDnsZones@2020-06-01' = [for p in privateLinks: {
  name: p.zone
  location: 'global'
}]

resource zoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = [for (p, i) in privateLinks: {
  parent: zones[i]
  name: 'link-${env}'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
}]

resource pes 'Microsoft.Network/privateEndpoints@2024-01-01' = [for p in privateLinks: {
  name: 'pe-${p.key}-${base}'
  location: location
  properties: {
    subnet: { id: vnet.properties.subnets[1].id }
    privateLinkServiceConnections: [
      { name: p.key, properties: { privateLinkServiceId: p.targetId, groupIds: [p.groupId] } }
    ]
  }
}]

resource peDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-01-01' = [for (p, i) in privateLinks: {
  parent: pes[i]
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: p.key, properties: { privateDnsZoneId: zones[i].id } }] }
}]

// ---------- role assignments for the workload identity (least privilege) ----------
resource raKvSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, uami.id, roles.kvSecretsUser)
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvSecretsUser)
  }
}

resource raKvCrypto 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, uami.id, roles.kvCryptoUser)
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvCryptoUser)
  }
}

resource raBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: st
  name: guid(st.id, uami.id, roles.blobContributor)
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobContributor)
  }
}

resource raAppi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: appi
  name: guid(appi.id, uami.id, roles.monitoringMetricsPublisher)
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringMetricsPublisher)
  }
}

// ---------- frontend: static web app ----------
resource swa 'Microsoft.Web/staticSites@2023-12-01' = {
  name: 'stapp-${base}-${suffix}'
  location: staticSiteLocation
  sku: { name: 'Standard', tier: 'Standard' }
  properties: { stagingEnvironmentPolicy: 'Disabled' }
}

// ---------- container apps ----------
resource acaEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${base}'
  location: location
  properties: {
    appLogsConfiguration: { destination: 'azure-monitor' }   // logs via the diagnostic setting below (no workspace key in the template)
    vnetConfiguration: { infrastructureSubnetId: vnet.properties.subnets[0].id, internal: false }
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    zoneRedundant: false
  }
}

resource acaDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: acaEnv
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource external 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-${workload}-ext-${env}'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${uami.id}': {} } }
  properties: {
    managedEnvironmentId: acaEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: { external: false, targetPort: 8080, allowInsecure: false }   // reachable only from inside the environment
      registries: [{ server: acr.properties.loginServer, identity: uami.id }]
    }
    template: {
      containers: [
        {
          name: 'externalapi'
          image: externalApiImage
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: [
            { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
            { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
            { name: 'KeyVault__Uri', value: kv.properties.vaultUri }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appi.properties.ConnectionString }
          ]
        }
      ]
      scale: { minReplicas: isProd ? 2 : 1, maxReplicas: 3 }
    }
  }
  dependsOn: [acrPull, raKvSecrets]
}

resource api 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-${workload}-api-${env}'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${uami.id}': {} } }
  properties: {
    managedEnvironmentId: acaEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: { external: true, targetPort: 8080, allowInsecure: false }
      registries: [{ server: acr.properties.loginServer, identity: uami.id }]
      // No `secrets:` block on purpose: nothing sensitive is passed as a setting.
    }
    template: {
      containers: [
        {
          name: 'api'
          image: apiImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
            { name: 'AZURE_CLIENT_ID', value: uami.properties.clientId }
            { name: 'KeyVault__Uri', value: kv.properties.vaultUri }
            { name: 'DataProtection__BlobUri', value: '${st.properties.primaryEndpoints.blob}${dpContainer.name}/keys.xml' }
            { name: 'DataProtection__KeyId', value: dpKey.properties.keyUriWithVersion }
            // Passwordless: the managed identity authenticates. Nothing here is a credential.
            { name: 'ConnectionStrings__Default', value: 'Server=tcp:${sql.properties.fullyQualifiedDomainName},1433;Database=${db.name};Authentication=Active Directory Managed Identity;User Id=${uami.properties.clientId};Encrypt=True' }
            { name: 'Cors__AllowedOrigins__0', value: 'https://${swa.properties.defaultHostname}' }
            { name: 'ExternalApi__BaseUrl', value: 'https://${external.properties.configuration.ingress.fqdn}' }
            { name: 'FrontDoor__Id', value: frontDoorId }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appi.properties.ConnectionString }
          ]
          probes: [
            { type: 'Liveness', httpGet: { path: '/health', port: 8080 }, periodSeconds: 30 }
            { type: 'Readiness', httpGet: { path: '/health', port: 8080 }, periodSeconds: 10 }
          ]
        }
      ]
      scale: { minReplicas: isProd ? 2 : 1, maxReplicas: 5, rules: [{ name: 'http', http: { metadata: { concurrentRequests: '50' } } }] }
    }
  }
  dependsOn: [acrPull, raKvSecrets, raKvCrypto, raBlob, pes, peDns]
}

// ---------- edge: front door + WAF ----------
resource waf 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: 'waf${workload}${env}${suffix}'
  location: 'global'
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    policySettings: { enabledState: 'Enabled', mode: wafMode, requestBodyCheck: 'Enabled' }
    managedRules: {
      managedRuleSets: [
        { ruleSetType: 'Microsoft_DefaultRuleSet', ruleSetVersion: '2.1', ruleSetAction: 'Block' }
        { ruleSetType: 'Microsoft_BotManagerRuleSet', ruleSetVersion: '1.1' }
      ]
    }
    customRules: {
      rules: [
        {
          name: 'RateLimitPerClientIp'
          priority: 100
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 300
          action: 'Block'
          matchConditions: [
            // "match every request" idiom: not from an address that cannot exist
            { matchVariable: 'RemoteAddr', operator: 'IPMatch', negateCondition: true, matchValue: ['255.255.255.255/32'] }
          ]
        }
      ]
    }
  }
}

resource afd 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: 'afd-${base}-${suffix}'
  location: 'global'
  sku: { name: 'Premium_AzureFrontDoor' }
}

resource afdEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: afd
  name: 'ep-${base}-${suffix}'
  location: 'global'
  properties: { enabledState: 'Enabled' }
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  parent: afd
  name: 'og-api'
  properties: {
    loadBalancingSettings: { sampleSize: 4, successfulSamplesRequired: 3 }
    healthProbeSettings: { probePath: '/health', probeRequestType: 'GET', probeProtocol: 'Https', probeIntervalInSeconds: 60 }
  }
}

resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  parent: originGroup
  name: 'api'
  properties: {
    hostName: api.properties.configuration.ingress.fqdn
    originHostHeader: api.properties.configuration.ingress.fqdn
    httpPort: 80
    httpsPort: 443
    priority: 1
    weight: 1000
    enforceCertificateNameCheck: true
  }
}

resource customDomain 'Microsoft.Cdn/profiles/customDomains@2024-02-01' = if (!empty(apiCustomDomain)) {
  parent: afd
  name: 'cd-api'
  properties: {
    hostName: apiCustomDomain
    tlsSettings: { certificateType: 'ManagedCertificate', minimumTlsVersion: 'TLS12' }
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  parent: afdEndpoint
  name: 'route-api'
  properties: {
    originGroup: { id: originGroup.id }
    patternsToMatch: ['/*']
    supportedProtocols: ['Http', 'Https']
    httpsRedirect: 'Enabled'
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    customDomains: !empty(apiCustomDomain) ? [{ id: customDomain.id }] : []
  }
  dependsOn: [origin]
}

resource wafAssoc 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {
  parent: afd
  name: 'sp-waf'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: { id: waf.id }
      associations: [
        {
          domains: concat([{ id: afdEndpoint.id }], !empty(apiCustomDomain) ? [{ id: customDomain.id }] : [])
          patternsToMatch: ['/*']
        }
      ]
    }
  }
}

resource afdDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: afd
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

// ---------- other diagnostics ----------
resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: kv
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource blobDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: blobSvc
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

// ---------- alerts ----------
resource ag 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'ag-${base}'
  location: 'global'
  properties: {
    groupShortName: take('sl${env}', 12)
    enabled: true
    emailReceivers: [{ name: 'oncall', emailAddress: alertEmail, useCommonAlertSchema: true }]
  }
}

var alertDefs = [
  {
    name: 'api-5xx'
    severity: 2
    threshold: 10
    query: 'AppRequests | where Success == false and toint(ResultCode) >= 500'
  }
  {
    name: 'waf-blocks'
    severity: 3
    threshold: 50
    query: 'AzureDiagnostics | where Category == "FrontDoorWebApplicationFirewallLog" and action_s == "Block"'
  }
  {
    name: 'keyvault-failures'
    severity: 2
    threshold: 5
    query: 'AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent" and httpStatusCode_d >= 400'
  }
  {
    name: 'sql-failed-logins'
    severity: 2
    threshold: 5
    query: 'AzureDiagnostics | where Category == "SQLSecurityAuditEvents" and action_id_s == "LGIF"'
  }
]

resource alerts 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = [for a in alertDefs: {
  name: 'alert-${a.name}-${env}'
  location: location
  properties: {
    displayName: 'SecLab ${env}: ${a.name}'
    severity: a.severity
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [law.id]
    criteria: {
      allOf: [
        {
          query: a.query
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: a.threshold
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [ag.id] }
  }
}]

// ---------- outputs (no secrets) ----------
output apiUrl string = 'https://${empty(apiCustomDomain) ? afdEndpoint.properties.hostName : apiCustomDomain}'
output staticSiteName string = swa.name
output frontDoorId string = afd.properties.frontDoorId
output workloadIdentityClientId string = uami.properties.clientId
output workloadIdentityName string = uami.name
output sqlServerFqdn string = sql.properties.fullyQualifiedDomainName
output keyVaultName string = kv.name
