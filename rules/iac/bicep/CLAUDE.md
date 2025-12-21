# Azure Bicep Security Rules

This document provides Azure Bicep-specific security rules for Claude Code. These rules ensure infrastructure code follows security best practices and compliance requirements for Azure deployments.

## Prerequisites

Before applying these rules, ensure familiarity with:

- [Core IaC Security Principles](../_core/iac-security.md) - Foundation for all infrastructure code
- [OWASP Top 10 2025](../../_core/owasp-2025.md) - Web application security fundamentals

---

## Rule 1: Secure Parameter Handling

**Level**: `strict`

**When**: Defining parameters that contain sensitive data (passwords, keys, tokens, connection strings)

**Do**:
```bicep
// Use @secure() decorator for sensitive parameters
@secure()
@description('Database administrator password')
param sqlAdminPassword string

@secure()
@description('Storage account access key')
param storageAccountKey string

@secure()
@description('Certificate password')
param certificatePassword string

// Reference Key Vault for secrets
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: 'company-keyvault-prod'
  scope: resourceGroup('shared-rg')
}

// Retrieve secrets from Key Vault
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: keyVault.getSecret('sql-admin-password')
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
  }
}

// Use Key Vault references in parameter files
// parameters.json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "sqlAdminPassword": {
      "reference": {
        "keyVault": {
          "id": "/subscriptions/{subscription-id}/resourceGroups/shared-rg/providers/Microsoft.KeyVault/vaults/company-keyvault"
        },
        "secretName": "sql-admin-password"
      }
    }
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Plain text sensitive parameter without @secure()
@description('Database administrator password')
param sqlAdminPassword string = 'P@ssw0rd123!'  // Exposed in logs and deployment history

// VULNERABLE: Hardcoded credentials
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-server-prod'
  location: resourceGroup().location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: 'SuperSecret123!'  // Never hardcode
  }
}

// VULNERABLE: Secrets in parameter files (committed to git)
// parameters.json
{
  "parameters": {
    "sqlAdminPassword": {
      "value": "P@ssw0rd123!"  // Exposed in version control
    }
  }
}

// VULNERABLE: API key in output (exposed in deployment history)
output apiKey string = 'sk-1234567890abcdef'
```

**Why**: Parameters without @secure() decorator are logged in deployment history, Azure CLI output, and PowerShell transcripts, exposing credentials to anyone with Reader access. Hardcoded secrets in Bicep files or parameter files are committed to version control, enabling credential theft and account takeover. Key Vault integration provides centralized secret management with access auditing and rotation capabilities.

**Refs**: CWE-798 (Hardcoded Credentials), CWE-532 (Insertion of Sensitive Information into Log File), Azure Security Baseline, NIST 800-53 IA-5

---

## Rule 2: Key Vault Security Configuration

**Level**: `strict`

**When**: Deploying Azure Key Vault resources

**Do**:
```bicep
// Secure Key Vault with RBAC and network restrictions
@description('Key Vault with security best practices')
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'  // Use 'premium' for HSM-backed keys
    }
    tenantId: subscription().tenantId
    
    // Enable RBAC instead of access policies
    enableRbacAuthorization: true
    
    // Security features
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    
    // Network security
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: [
        {
          id: subnet.id
          ignoreMissingVnetServiceEndpoint: false
        }
      ]
    }
  }
}

// Enable diagnostic logging
resource kvDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'keyvault-diagnostics'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Store secrets with metadata
resource databasePassword 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'database-password'
  properties: {
    value: generatePassword
    contentType: 'text/plain'
    attributes: {
      enabled: true
    }
  }
  tags: {
    environment: 'production'
    purpose: 'database-authentication'
    rotationSchedule: '90-days'
  }
}

// Use managed identity for access
resource appServiceIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'app-identity'
  location: resourceGroup().location
}

// Grant Key Vault Secrets User role
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appServiceIdentity.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appServiceIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Insecure Key Vault configuration
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'insecure-keyvault'
  location: resourceGroup().location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    
    // VULNERABLE: Legacy access policies instead of RBAC
    enableRbacAuthorization: false
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: 'hardcoded-object-id'  // Bad practice
        permissions: {
          secrets: ['all']  // Excessive permissions
        }
      }
    ]
    
    // VULNERABLE: Soft delete disabled
    enableSoftDelete: false
    
    // VULNERABLE: No purge protection
    enablePurgeProtection: false
    
    // VULNERABLE: Public network access allowed
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'  // Allows all traffic
    }
  }
}

// VULNERABLE: No diagnostic logging
// Missing diagnosticSettings resource

// VULNERABLE: Using access policies with wildcards
resource keyVault2 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-insecure2'
  location: resourceGroup().location
  properties: {
    accessPolicies: [
      {
        permissions: {
          keys: ['*']  // All key permissions
          secrets: ['*']  // All secret permissions
          certificates: ['*']  // All certificate permissions
        }
      }
    ]
  }
}
```

**Why**: Key Vault stores critical secrets and encryption keys. Public network access exposes secrets to internet-based attacks. Disabled soft delete and purge protection enable permanent secret deletion, preventing recovery from ransomware or insider threats. Access policies without RBAC lack fine-grained control and audit trails. Missing diagnostic logging prevents detection of unauthorized access attempts and security incidents.

**Refs**: CWE-311 (Missing Encryption), Azure Key Vault Security Baseline, NIST 800-53 SC-28, CIS Azure 8.1-8.7

---

## Rule 3: Storage Account Security

**Level**: `strict`

**When**: Deploying Azure Storage Accounts

**Do**:
```bicep
// Secure storage account configuration
@description('Secure storage account with best practices')
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  sku: {
    name: 'Standard_GRS'  // Geo-redundant for production
  }
  kind: 'StorageV2'
  properties: {
    // Enforce HTTPS only
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    
    // Disable public blob access
    allowBlobPublicAccess: false
    
    // Disable shared key access (use Azure AD only)
    allowSharedKeyAccess: false
    
    // Enable infrastructure encryption (double encryption)
    encryption: {
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
        file: {
          enabled: true
          keyType: 'Account'
        }
      }
      keySource: 'Microsoft.Keyvault'
      keyvaultproperties: {
        keyname: 'storage-encryption-key'
        keyvaulturi: keyVault.properties.vaultUri
      }
    }
    
    // Network restrictions
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: [
        {
          id: subnet.id
          action: 'Allow'
        }
      ]
    }
    
    // Enable advanced threat protection
    azureFilesIdentityBasedAuthentication: {
      directoryServiceOptions: 'AADKERB'
    }
  }
}

// Enable blob versioning and soft delete
resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    isVersioningEnabled: true
    changeFeed: {
      enabled: true
      retentionInDays: 90
    }
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    lastAccessTimeTrackingPolicy: {
      enable: true
      name: 'AccessTimeTracking'
      trackingGranularityInDays: 1
      blobType: ['blockBlob']
    }
  }
}

// Enable diagnostic logging
resource storageDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'storage-diagnostics'
  scope: storageAccount
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    metrics: [
      {
        category: 'Transaction'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Enable blob diagnostic logging
resource blobDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'blob-diagnostics'
  scope: blobServices
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'StorageRead'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'StorageWrite'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'StorageDelete'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
    metrics: [
      {
        category: 'Transaction'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Use private endpoints
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-storage-blob'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: subnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'storage-blob-connection'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: ['blob']
        }
      }
    ]
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Insecure storage account
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'insecurestorage'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    // VULNERABLE: HTTP allowed
    supportsHttpsTrafficOnly: false
    
    // VULNERABLE: Old TLS version
    minimumTlsVersion: 'TLS1_0'
    
    // VULNERABLE: Public blob access allowed
    allowBlobPublicAccess: true
    
    // VULNERABLE: Shared key access enabled
    allowSharedKeyAccess: true
    
    // VULNERABLE: No customer-managed encryption
    encryption: {
      services: {
        blob: { enabled: true }
      }
      keySource: 'Microsoft.Storage'  // Microsoft-managed keys only
    }
    
    // VULNERABLE: Public network access
    networkAcls: {
      defaultAction: 'Allow'  // Open to internet
    }
  }
}

// VULNERABLE: No versioning or soft delete
resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    isVersioningEnabled: false
    deleteRetentionPolicy: {
      enabled: false  // Cannot recover deleted data
    }
  }
}

// VULNERABLE: No diagnostic logging
// Missing diagnosticSettings

// VULNERABLE: Publicly accessible container
resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobServices
  name: 'public-data'
  properties: {
    publicAccess: 'Container'  // Anonymous access allowed
  }
}
```

**Why**: HTTP traffic exposes data in transit to interception and tampering. Public blob access enables data exfiltration without authentication. Shared key access cannot be audited per-user and increases attack surface. Microsoft-managed keys provide no customer control over encryption. Open network access allows attacks from any IP address. Missing versioning and soft delete prevent recovery from accidental deletion or ransomware attacks. Missing logs prevent detection of unauthorized access and data breaches.

**Refs**: CWE-319 (Cleartext Transmission), CWE-311 (Missing Encryption), Azure Storage Security Baseline, NIST 800-53 SC-8, CIS Azure

---

## Rule 4: SQL Database Security

**Level**: `strict`

**When**: Deploying Azure SQL Database or Managed Instance

**Do**:
```bicep
// Secure SQL Server configuration
@description('Secure SQL Server with best practices')
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: keyVault.getSecret('sql-admin-password')
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
    
    // Enable Azure AD authentication
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'Group'
      login: 'SQL Admins'
      sid: sqlAdminGroupId
      tenantId: subscription().tenantId
      azureADOnlyAuthentication: true  // Disable SQL authentication
    }
  }
}

// Secure SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'production-db'
  location: resourceGroup().location
  sku: {
    name: 'S3'
    tier: 'Standard'
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: 268435456000
    
    // Enable encryption
    transparentDataEncryption: 'Enabled'
  }
}

// Enable Advanced Data Security
resource securityAlertPolicy 'Microsoft.Sql/servers/securityAlertPolicies@2023-05-01-preview' = {
  parent: sqlServer
  name: 'Default'
  properties: {
    state: 'Enabled'
    emailAccountAdmins: true
    emailAddresses: ['security@company.com']
    retentionDays: 90
    disabledAlerts: []
  }
}

// Enable vulnerability assessment
resource vulnerabilityAssessment 'Microsoft.Sql/servers/vulnerabilityAssessments@2023-05-01-preview' = {
  parent: sqlServer
  name: 'Default'
  properties: {
    storageContainerPath: '${storageAccount.properties.primaryEndpoints.blob}vulnerability-assessment'
    recurringScans: {
      isEnabled: true
      emailSubscriptionAdmins: true
      emails: ['security@company.com']
    }
  }
}

// Enable auditing
resource auditingSettings 'Microsoft.Sql/servers/auditingSettings@2023-05-01-preview' = {
  parent: sqlServer
  name: 'default'
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true
    retentionDays: 90
    auditActionsAndGroups: [
      'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP'
      'FAILED_DATABASE_AUTHENTICATION_GROUP'
      'BATCH_COMPLETED_GROUP'
    ]
  }
}

// Enable diagnostic logging
resource sqlDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'sql-diagnostics'
  scope: sqlDatabase
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'SQLSecurityAuditEvents'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'SQLInsights'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
    metrics: [
      {
        category: 'Basic'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Use private endpoint
resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-sql'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: subnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'sql-connection'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: ['sqlServer']
        }
      }
    ]
  }
}

// Configure firewall (only if private endpoint not used)
resource firewallRule 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = if (usePublicEndpoint) {
  parent: sqlServer
  name: 'AllowSpecificIP'
  properties: {
    startIpAddress: '203.0.113.0'
    endIpAddress: '203.0.113.255'
    // Never use: startIpAddress: '0.0.0.0', endIpAddress: '255.255.255.255'
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Insecure SQL Server
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-insecure'
  location: resourceGroup().location
  properties: {
    administratorLogin: 'sa'  // Weak username
    administratorLoginPassword: 'Password123!'  // Hardcoded
    version: '12.0'
    
    // VULNERABLE: Old TLS version
    minimalTlsVersion: '1.0'
    
    // VULNERABLE: Public access enabled
    publicNetworkAccess: 'Enabled'
    
    // VULNERABLE: No Azure AD authentication
    // administrators not configured
  }
}

// VULNERABLE: Open firewall
resource firewallRule 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: sqlServer
  name: 'AllowAll'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'  // Allows entire internet
  }
}

// VULNERABLE: Azure services rule
resource azureServicesRule 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: sqlServer
  name: 'AllowAllWindowsAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'  // Allows all Azure services
  }
}

// VULNERABLE: No threat detection
// Missing securityAlertPolicy

// VULNERABLE: No auditing
// Missing auditingSettings

// VULNERABLE: No diagnostic logging
// Missing diagnosticSettings

// VULNERABLE: TDE disabled
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'db'
  properties: {
    // transparentDataEncryption not configured
  }
}
```

**Why**: Public SQL Server access with open firewall rules exposes databases to brute force attacks and credential stuffing. SQL authentication without Azure AD prevents MFA enforcement and centralized access management. Missing TDE exposes data at rest on physical media. Disabled threat detection and auditing prevent detection of SQL injection attempts, suspicious access patterns, and data exfiltration. Old TLS versions are vulnerable to downgrade attacks and cryptographic weaknesses.

**Refs**: CWE-306 (Missing Authentication), CWE-284 (Improper Access Control), Azure SQL Security Baseline, NIST 800-53 AC-3, CIS Azure

---

## Rule 5: Network Security Groups and Rules

**Level**: `strict`

**When**: Deploying Network Security Groups and security rules

**Do**:
```bicep
// Secure NSG with least privilege rules
@description('Network Security Group with restrictive rules')
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-app-subnet'
  location: resourceGroup().location
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPSFromLoadBalancer'
        properties: {
          description: 'Allow HTTPS traffic from Azure Load Balancer'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHealthProbe'
        properties: {
          description: 'Allow health probe from Load Balancer'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          description: 'Deny all other inbound traffic'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4096
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHTTPSToSQL'
        properties: {
          description: 'Allow HTTPS to SQL Private Endpoint'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '1433'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: '10.0.2.0/24'  // SQL subnet CIDR
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
      {
        name: 'AllowHTTPSToStorage'
        properties: {
          description: 'Allow HTTPS to Storage'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'Storage'
          access: 'Allow'
          priority: 110
          direction: 'Outbound'
        }
      }
      {
        name: 'DenyInternetOutbound'
        properties: {
          description: 'Deny outbound internet access'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Internet'
          access: 'Deny'
          priority: 4000
          direction: 'Outbound'
        }
      }
    ]
  }
}

// Enable NSG flow logs
resource nsgFlowLog 'Microsoft.Network/networkWatchers/flowLogs@2023-05-01' = {
  name: '${networkWatcher.name}/nsg-flowlog'
  location: resourceGroup().location
  properties: {
    targetResourceId: nsg.id
    storageId: storageAccount.id
    enabled: true
    retentionPolicy: {
      days: 90
      enabled: true
    }
    format: {
      type: 'JSON'
      version: 2
    }
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceResourceId: logAnalyticsWorkspace.id
        trafficAnalyticsInterval: 10
      }
    }
  }
}

// Enable diagnostic logging
resource nsgDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'nsg-diagnostics'
  scope: nsg
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'NetworkSecurityGroupEvent'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'NetworkSecurityGroupRuleCounter'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Overly permissive NSG
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-insecure'
  location: resourceGroup().location
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'  // VULNERABLE: Any source
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowSSH'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: 'Internet'  // VULNERABLE: SSH from internet
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowRDP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '0.0.0.0/0'  // VULNERABLE: RDP from anywhere
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowAllOutbound'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'  // VULNERABLE: Any destination
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
    ]
  }
}

// VULNERABLE: No NSG flow logs
// Missing flowLog configuration

// VULNERABLE: No diagnostic logging
// Missing diagnosticSettings
```

**Why**: Wildcard source addresses (*, 0.0.0.0/0, Internet) allow attacks from any IP address including malicious actors. SSH and RDP exposed to internet enable brute force attacks and credential stuffing. Overly permissive outbound rules allow data exfiltration and command-and-control communication. Missing flow logs prevent detection of network scanning, lateral movement, and suspicious traffic patterns. Missing diagnostics prevent security monitoring and incident response.

**Refs**: CWE-284 (Improper Access Control), CWE-923 (Improper Restriction of Communication), Azure NSG Security Baseline, NIST 800-53 SC-7, CIS Azure

---

## Rule 6: Managed Identity Usage

**Level**: `strict`

**When**: Deploying resources that need to authenticate to other Azure services

**Do**:
```bicep
// Use system-assigned managed identity
@description('App Service with managed identity')
resource appService 'Microsoft.Web/sites@2023-01-01' = {
  name: 'app-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      alwaysOn: true
      
      // Reference Key Vault using managed identity
      keyVaultReferenceIdentity: 'SystemAssigned'
      appSettings: [
        {
          name: 'DatabaseConnectionString'
          value: '@Microsoft.KeyVault(VaultName=${keyVault.name};SecretName=db-connection-string)'
        }
        {
          name: 'StorageAccountName'
          value: storageAccount.name
        }
      ]
    }
  }
}

// Grant managed identity access to resources
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appService.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appService.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, appService.id, 'Storage Blob Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: appService.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Use user-assigned managed identity for shared access
resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-shared-services'
  location: resourceGroup().location
}

resource vmWithUserIdentity 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: 'vm-app'
  location: resourceGroup().location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentity.id}': {}
    }
  }
  properties: {
    // VM properties
  }
}

// Azure Functions with managed identity
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'func-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccount.name
          // Use managed identity connection - no connection string needed
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
      ]
    }
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Using connection strings instead of managed identity
resource appService 'Microsoft.Web/sites@2023-01-01' = {
  name: 'app-insecure'
  location: resourceGroup().location
  properties: {
    siteConfig: {
      appSettings: [
        {
          name: 'DatabaseConnectionString'
          // VULNERABLE: Connection string with embedded credentials
          value: 'Server=tcp:sql.database.windows.net;Database=mydb;User ID=admin;Password=P@ssw0rd!'
        }
        {
          name: 'StorageConnectionString'
          // VULNERABLE: Storage account key in plain text
          value: 'DefaultEndpointsProtocol=https;AccountName=storage;AccountKey=abc123...;EndpointSuffix=core.windows.net'
        }
        {
          name: 'ServiceBusConnectionString'
          // VULNERABLE: Service Bus connection string
          value: 'Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=key123...'
        }
      ]
    }
  }
}

// VULNERABLE: Using SAS tokens in configuration
resource containerInstance 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: 'container-insecure'
  location: resourceGroup().location
  properties: {
    containers: [
      {
        name: 'app'
        properties: {
          environmentVariables: [
            {
              name: 'STORAGE_SAS_TOKEN'
              // VULNERABLE: SAS token in environment variable
              value: '?sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacupiytfx...'
            }
          ]
        }
      }
    ]
  }
}

// VULNERABLE: No managed identity
resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: 'vm-no-identity'
  location: resourceGroup().location
  // Missing: identity configuration
  properties: {
    // VM config without managed identity
  }
}
```

**Why**: Connection strings and access keys in configuration are static credentials that cannot be rotated without application changes and are exposed in deployment history and logs. Managed identities provide automatically rotated credentials with Azure AD integration, enabling MFA enforcement and conditional access policies. Managed identities eliminate credential theft risk and simplify access management through RBAC. Missing managed identity forces use of less secure authentication methods and increases operational overhead.

**Refs**: CWE-798 (Hardcoded Credentials), Azure Managed Identity Best Practices, NIST 800-53 IA-5, CIS Azure

---

## Rule 7: Resource Locks for Critical Resources

**Level**: `strict`

**When**: Deploying critical infrastructure resources that should not be accidentally deleted

**Do**:
```bicep
// Apply CanNotDelete lock to critical resources
@description('Production Key Vault with delete protection')
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-prod-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    // Key Vault properties
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
  }
  tags: {
    environment: 'production'
    criticality: 'high'
  }
}

resource keyVaultLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'keyVaultLock'
  scope: keyVault
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of production Key Vault containing critical secrets'
  }
}

// Lock for production database
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-prod-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    // SQL Server properties
  }
  tags: {
    environment: 'production'
    criticality: 'high'
  }
}

resource sqlServerLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'sqlServerLock'
  scope: sqlServer
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of production SQL Server and all databases'
  }
}

// Lock for storage account with critical data
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stprod${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    // Storage account properties
  }
  tags: {
    environment: 'production'
    criticality: 'high'
    dataClassification: 'confidential'
  }
}

resource storageLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'storageLock'
  scope: storageAccount
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of production storage containing customer data'
  }
}

// Conditional lock based on environment
param environment string = 'production'

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-${environment}'
  location: resourceGroup().location
  properties: {
    // VNet properties
  }
}

resource vnetLock 'Microsoft.Authorization/locks@2020-05-01' = if (environment == 'production') {
  name: 'vnetLock'
  scope: virtualNetwork
  properties: {
    level: 'CanNotDelete'
    notes: 'Production VNet is locked to prevent accidental deletion'
  }
}

// Resource group lock (inherited by all resources)
resource resourceGroupLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'resourceGroupLock'
  properties: {
    level: 'CanNotDelete'
    notes: 'Production resource group is locked to prevent accidental deletion of critical infrastructure'
  }
}
```

**Don't**:
```bicep
// VULNERABLE: No locks on critical resources
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-prod-critical'
  location: resourceGroup().location
  properties: {
    // Critical Key Vault without lock
  }
  // Missing: resource lock
}

resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-prod-critical'
  location: resourceGroup().location
  properties: {
    // Production database without lock
  }
  // Missing: resource lock
}

// VULNERABLE: Using ReadOnly lock incorrectly
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stprod'
  location: resourceGroup().location
}

resource storageLock 'Microsoft.Authorization/locks@2020-05-01' = {
  scope: storageAccount
  properties: {
    level: 'ReadOnly'  // WRONG: Prevents legitimate updates and data writes
    notes: 'Locked'
  }
}
```

**Why**: Accidental deletion of critical infrastructure causes service outages, data loss, and expensive recovery operations. Azure's soft-delete and backup features require time to restore, causing extended downtime. Resource locks prevent deletion through portal, CLI, API, and Infrastructure-as-Code operations. CanNotDelete locks allow updates while preventing deletion, maintaining operational flexibility. Missing locks on production resources enable insider threats and human error to cause catastrophic failures.

**Refs**: Azure Resource Manager Locks, NIST 800-53 CP-9 (Information System Backup), CIS Azure

---

## Rule 8: Diagnostic Settings and Logging

**Level**: `strict`

**When**: Deploying any Azure resource that supports diagnostic settings

**Do**:
```bicep
// Log Analytics Workspace for centralized logging
@description('Log Analytics Workspace for all diagnostic logs')
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90  // Minimum 90 days for compliance
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Disabled'
    publicNetworkAccessForQuery: 'Disabled'
  }
}

// Storage account for long-term log archival
resource logStorageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stlogs${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

// Comprehensive diagnostic settings for Key Vault
resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'keyvault-diagnostics'
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    storageAccountId: logStorageAccount.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Diagnostic settings for SQL Database
resource sqlDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'sql-diagnostics'
  scope: sqlDatabase
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    storageAccountId: logStorageAccount.id
    logs: [
      {
        category: 'SQLSecurityAuditEvents'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'DevOpsOperationsAudit'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'SQLInsights'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Errors'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Timeouts'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Blocks'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Deadlocks'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
    metrics: [
      {
        category: 'Basic'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'InstanceAndAppAdvanced'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Diagnostic settings for App Service
resource appServiceDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'appservice-diagnostics'
  scope: appService
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'AppServiceAppLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'AppServiceAuditLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

// Activity log export to Log Analytics
resource activityLogDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-log-diagnostics'
  scope: subscription()
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    storageAccountId: logStorageAccount.id
    logs: [
      {
        category: 'Administrative'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'Security'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
      {
        category: 'ServiceHealth'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Alert'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'Policy'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
  }
}
```

**Don't**:
```bicep
// VULNERABLE: No diagnostic settings
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-no-logs'
  location: resourceGroup().location
  properties: {
    // Key Vault without diagnostic settings
  }
}
// Missing: diagnosticSettings

resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-no-logs'
  location: resourceGroup().location
  properties: {
    // SQL Server without diagnostic settings
  }
}
// Missing: diagnosticSettings

// VULNERABLE: Insufficient retention period
resource insufficientDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 7  // Too short for compliance
        }
      }
    ]
  }
}

// VULNERABLE: Partial logging
resource partialDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: sqlDatabase
  properties: {
    logs: [
      {
        category: 'Errors'
        enabled: true
      }
      // Missing: SQLSecurityAuditEvents, DevOpsOperationsAudit, etc.
    ]
  }
}

// VULNERABLE: No storage account for archival
resource noArchival 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    // Missing: storageAccountId for long-term archival
  }
}
```

**Why**: Missing diagnostic settings prevent detection of security incidents, unauthorized access, and configuration changes. Insufficient retention periods violate compliance requirements (GDPR, HIPAA, PCI DSS) and prevent forensic analysis of historical security events. Partial logging creates blind spots that attackers exploit to hide malicious activity. Missing long-term archival to storage accounts loses audit trails needed for compliance audits and legal investigations. Activity log monitoring detects subscription-level attacks like privilege escalation and resource manipulation.

**Refs**: CWE-778 (Insufficient Logging), Azure Monitor Best Practices, NIST 800-53 AU-2/AU-3/AU-11, CIS Azure, GDPR Article 32

---

## Rule 9: Azure Policy Compliance

**Level**: `strict`

**When**: Deploying resources that must comply with organizational or regulatory policies

**Do**:
```bicep
// Deploy Azure Policy assignments for compliance
@description('Deploy required tags policy')
resource requireTagsPolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'require-tags-policy'
  properties: {
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4f9dc7db-30c1-420c-b61a-e1d640128d26'
    displayName: 'Require specific tags on resources'
    description: 'Enforces required tags on all resources for compliance and cost tracking'
    enforcementMode: 'Default'
    parameters: {
      tagNames: {
        value: [
          'Environment'
          'CostCenter'
          'Owner'
          'Criticality'
          'DataClassification'
        ]
      }
    }
  }
}

// Deploy allowed locations policy
resource allowedLocationsPolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'allowed-locations-policy'
  properties: {
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
    displayName: 'Allowed locations'
    description: 'Restricts resource deployment to compliant regions'
    parameters: {
      listOfAllowedLocations: {
        value: [
          'eastus2'
          'westus2'
          'northeurope'
        ]
      }
    }
  }
}

// Deploy encryption requirement policy
resource storageEncryptionPolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'storage-encryption-policy'
  properties: {
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4733ea7b-a883-42fe-8cac-97454c2a9e4a'
    displayName: 'Storage accounts should use customer-managed keys for encryption'
    description: 'Enforces CMK encryption on all storage accounts'
    enforcementMode: 'Default'
  }
}

// Tagging compliance in resources
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  tags: {
    Environment: 'production'
    CostCenter: 'engineering-12345'
    Owner: 'team@company.com'
    Criticality: 'high'
    DataClassification: 'confidential'
    ComplianceFramework: 'PCI-DSS-4.0'
    BackupRequired: 'true'
    DisasterRecovery: 'enabled'
  }
  sku: {
    name: 'Standard_GRS'
  }
  kind: 'StorageV2'
  properties: {
    // Storage properties
  }
}

// Use built-in policies for security compliance
resource defensivePolicies 'Microsoft.Authorization/policySetAssignments@2023-04-01' = {
  name: 'azure-security-benchmark'
  properties: {
    policySetDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
    displayName: 'Azure Security Benchmark'
    description: 'Applies Azure Security Benchmark policies'
    enforcementMode: 'Default'
  }
}

// Deploy custom policy for organization requirements
resource customPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'deny-public-endpoints'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    displayName: 'Deny resources with public endpoints'
    description: 'Denies creation of resources with public network access enabled'
    policyRule: {
      if: {
        anyOf: [
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Storage/storageAccounts'
              }
              {
                field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess'
                notEquals: 'Disabled'
              }
            ]
          }
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Sql/servers'
              }
              {
                field: 'Microsoft.Sql/servers/publicNetworkAccess'
                notEquals: 'Disabled'
              }
            ]
          }
        ]
      }
      then: {
        effect: 'Deny'
      }
    }
  }
}
```

**Don't**:
```bicep
// VULNERABLE: No policy compliance
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stnopolicy'
  location: 'centralus'  // May not be compliant region
  tags: {}  // Missing required tags
  properties: {
    // No compliance checks
  }
}

// VULNERABLE: Policy in audit mode only
resource auditOnlyPolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  properties: {
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4733ea7b-a883-42fe-8cac-97454c2a9e4a'
    enforcementMode: 'DoNotEnforce'  // Policy violations allowed
  }
}

// VULNERABLE: Incomplete tagging
resource poorTags 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-poortagging'
  location: resourceGroup().location
  tags: {
    Name: 'my-keyvault'  // Only cosmetic tag, no compliance info
  }
}

// VULNERABLE: No policy assignments
// Missing policy assignments for:
// - Required tags
// - Allowed locations
// - Encryption requirements
// - Network restrictions
// - Security benchmarks
```

**Why**: Azure Policy enforces organizational standards and compliance requirements automatically across all resources. Missing policy assignments allow non-compliant resources that violate security baselines, data residency requirements, and regulatory controls. Audit-only policies provide visibility but don't prevent violations, allowing insecure configurations in production. Incomplete tagging prevents cost allocation, compliance reporting, and automated lifecycle management. Policy compliance enables continuous security validation and prevents configuration drift.

**Refs**: Azure Policy Documentation, CIS Azure, NIST 800-53 CM-7, ISO 27001 A.12.6

---

## Rule 10: Module Security and Validation

**Level**: `strict`

**When**: Creating or consuming Bicep modules

**Do**:
```bicep
// Secure module from verified registry
module storageModule 'br:myregistry.azurecr.io/bicep/modules/storage:v1.2.3' = {
  name: 'storageDeployment'
  params: {
    storageAccountName: 'st${uniqueString(resourceGroup().id)}'
    location: resourceGroup().location
    skuName: 'Standard_GRS'
    enablePublicAccess: false
    enableHttpsOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

// Module with parameter validation
@description('Storage account module with security validations')
@minLength(3)
@maxLength(24)
param storageAccountName string

@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_RAGRS'
  'Standard_ZRS'
  'Premium_LRS'
])
param skuName string = 'Standard_GRS'

@allowed([
  'TLS1_2'
  'TLS1_3'
])
param minimumTlsVersion string = 'TLS1_2'

@description('Whether to enable public blob access')
param enablePublicAccess bool = false

@description('Location for all resources')
param location string = resourceGroup().location

@description('Tags to apply to all resources')
param tags object = {
  Environment: 'production'
  ManagedBy: 'Bicep'
}

// Validate sensitive parameters
@secure()
@minLength(12)
param sqlAdminPassword string

// Module with output validation
output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name

// Don't output sensitive values
// output primaryKey string = storageAccount.listKeys().keys[0].value  // Never do this

// Local module reference with metadata
@description('Network security group module')
@sys.metadata({
  version: '1.0.0'
  author: 'security@company.com'
  lastUpdated: '2025-01-15'
})
module nsgModule './modules/network/nsg.bicep' = {
  name: 'nsgDeployment'
  params: {
    nsgName: 'nsg-app-subnet'
    location: resourceGroup().location
    securityRules: securityRules
  }
}

// Module with dependency management
module vnetModule 'br:myregistry.azurecr.io/bicep/modules/vnet:v2.1.0' = {
  name: 'vnetDeployment'
  params: {
    vnetName: 'vnet-prod'
    location: resourceGroup().location
  }
}

module appServiceModule 'br:myregistry.azurecr.io/bicep/modules/appservice:v1.5.0' = {
  name: 'appServiceDeployment'
  dependsOn: [
    vnetModule
  ]
  params: {
    appName: 'app-prod'
    subnetId: vnetModule.outputs.appSubnetId
  }
}

// Private module registry configuration
// .bicepconfig.json
{
  "moduleAliases": {
    "br": {
      "company": {
        "registry": "companyregistry.azurecr.io",
        "modulePath": "bicep/modules"
      }
    }
  },
  "analyzers": {
    "core": {
      "enabled": true,
      "rules": {
        "no-hardcoded-env-urls": {
          "level": "error"
        },
        "no-unused-params": {
          "level": "warning"
        },
        "secure-params-in-nested-deploy": {
          "level": "error"
        }
      }
    }
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Module from unverified source
module unsafeModule 'https://raw.githubusercontent.com/unknown/repo/main/module.bicep' = {
  name: 'unsafeDeployment'
  // VULNERABLE: No version pinning, untrusted source
}

// VULNERABLE: No parameter validation
param storageAccountName string  // No length validation
param skuName string  // No allowed values
param password string  // Missing @secure()

// VULNERABLE: Exposing sensitive outputs
output adminPassword string = sqlAdminPassword  // Exposed in deployment history
output storageAccountKey string = storageAccount.listKeys().keys[0].value  // Credential exposure
output connectionString string = 'Server=${sqlServer.properties.fullyQualifiedDomainName};...'  // Exposed

// VULNERABLE: No metadata
module noMetadataModule './module.bicep' = {
  // No version info, author, or documentation
}

// VULNERABLE: Hardcoded values in module
module badModule './bad.bicep' = {
  params: {
    adminPassword: 'P@ssw0rd123!'  // Hardcoded credential
    allowedIPs: ['0.0.0.0/0']  // Insecure default
  }
}

// VULNERABLE: Module without validation
// bad.bicep
param storageAccountName string
// No validation - allows invalid names

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName  // May fail deployment or create insecure config
}
```

**Why**: Unverified modules from public repositories can contain backdoors, credential harvesters, or vulnerable configurations. Missing version pinning in module references enables supply chain attacks through automatic updates to compromised versions. Unvalidated parameters allow invalid or insecure configurations that fail deployment or create security vulnerabilities. Sensitive outputs in modules expose credentials in deployment history accessible to all readers. Missing metadata prevents security audits and impact analysis during incident response.

**Refs**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), Azure Bicep Best Practices, NIST 800-53 SA-12, Supply Chain Security

---

## Rule 11: Private Endpoints and Network Isolation

**Level**: `strict`

**When**: Deploying PaaS services that support private endpoints

**Do**:
```bicep
// Virtual network for private endpoints
resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-prod'
  location: resourceGroup().location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.1.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'snet-data'
        properties: {
          addressPrefix: '10.0.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
          serviceEndpoints: []  // Use private endpoints instead
        }
      }
    ]
  }
}

// Storage account with private endpoint
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Disabled'  // Block public access
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-storage-blob'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: vnet.properties.subnets[1].id
    }
    privateLinkServiceConnections: [
      {
        name: 'storage-blob-connection'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: ['blob']
          requestMessage: 'Private endpoint for blob storage'
        }
      }
    ]
  }
}

// Private DNS zone for storage blob
resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}

resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: '${vnet.name}-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-05-01' = {
  parent: storagePrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob-config'
        properties: {
          privateDnsZoneId: privateDnsZone.id
        }
      }
    ]
  }
}

// Key Vault with private endpoint
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-keyvault'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: vnet.properties.subnets[1].id
    }
    privateLinkServiceConnections: [
      {
        name: 'keyvault-connection'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: ['vault']
        }
      }
    ]
  }
}

// SQL Server with private endpoint
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Disabled'
  }
}

resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-sql'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: vnet.properties.subnets[1].id
    }
    privateLinkServiceConnections: [
      {
        name: 'sql-connection'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: ['sqlServer']
        }
      }
    ]
  }
}

// Cosmos DB with private endpoint
resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
  name: 'cosmos-${uniqueString(resourceGroup().id)}'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Disabled'
    ipRules: []
    isVirtualNetworkFilterEnabled: false
  }
}

resource cosmosPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-cosmos'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: vnet.properties.subnets[1].id
    }
    privateLinkServiceConnections: [
      {
        name: 'cosmos-connection'
        properties: {
          privateLinkServiceId: cosmosAccount.id
          groupIds: ['Sql']
        }
      }
    ]
  }
}
```

**Don't**:
```bicep
// VULNERABLE: Public network access enabled
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stpublic'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Enabled'  // Exposed to internet
    networkAcls: {
      defaultAction: 'Allow'  // No restrictions
    }
  }
}
// Missing: private endpoint

// VULNERABLE: Using service endpoints instead of private endpoints
resource vnetWithServiceEndpoints 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-serviceendpoints'
  location: resourceGroup().location
  properties: {
    subnets: [
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.1.0/24'
          serviceEndpoints: [
            {
              service: 'Microsoft.Storage'  // VULNERABLE: Traffic still uses public IPs
            }
            {
              service: 'Microsoft.Sql'
            }
          ]
        }
      }
    ]
  }
}

// VULNERABLE: Private endpoint without DNS integration
resource badPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-no-dns'
  location: resourceGroup().location
  properties: {
    subnet: {
      id: subnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'connection'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: ['blob']
        }
      }
    ]
  }
  // Missing: privateDnsZoneGroup - DNS resolution won't work
}

// VULNERABLE: Mixed public and private access
resource mixedAccess 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stmixed'
  location: resourceGroup().location
  properties: {
    publicNetworkAccess: 'Enabled'  // Public access while using private endpoint
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource unnecessaryPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pe-confused'
  properties: {
    privateLinkServiceId: mixedAccess.id
    // Defeats purpose of private endpoint
  }
}
```

**Why**: Public network access exposes PaaS services to internet-based attacks including brute force, credential stuffing, and DDoS. Service endpoints improve security but traffic still uses Azure public IP space and is visible to Azure backbone routers. Private endpoints provide true network isolation with private IP addresses, eliminating public exposure. Missing DNS integration causes connection failures as applications try to reach public endpoints. Mixed public/private access creates security confusion and attack surface. Private endpoints enable network segmentation and comply with data residency requirements.

**Refs**: CWE-923 (Improper Restriction of Communication), Azure Private Link Best Practices, NIST 800-53 SC-7, CIS Azure 6.5

---

## Rule 12: Automated Security Validation

**Level**: `strict`

**When**: Implementing CI/CD pipelines for Bicep deployments

**Do**:
```yaml
# GitHub Actions workflow with security validation
name: Bicep Security Validation

on:
  pull_request:
    paths:
      - '**.bicep'
      - '**.bicepparam'
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  id-token: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Bicep
        run: |
          az bicep install
          az bicep upgrade

      - name: Bicep Build
        run: |
          az bicep build --file ./main.bicep
          # Fails on syntax errors

      - name: Bicep Linter
        run: |
          az bicep build --file ./main.bicep --diagnostics-format sarif --outfile bicep-results.sarif
          # Generates SARIF output for GitHub Code Scanning

      - name: Upload Bicep Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bicep-results.sarif
          category: bicep-analysis

      - name: PSRule for Azure
        uses: microsoft/ps-rule@v2
        with:
          modules: 'PSRule.Rules.Azure'
          inputPath: './main.bicep'
          outputFormat: 'Sarif'
          outputPath: 'psrule-results.sarif'

      - name: Upload PSRule Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: psrule-results.sarif
          category: psrule-analysis

      - name: Microsoft Security DevOps
        uses: microsoft/security-devops-action@v1
        id: msdo
        with:
          categories: 'IaC'

      - name: Upload MSDO Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.msdo.outputs.sarifFile }}
          category: msdo-analysis

      - name: What-If Analysis
        id: whatif
        run: |
          az deployment group what-if \
            --resource-group rg-prod \
            --template-file ./main.bicep \
            --parameters @main.parameters.json \
            --result-format FullResourcePayloads \
            > whatif-output.txt

      - name: Review What-If Output
        run: |
          # Fail if any deletions detected
          if grep -q "Delete" whatif-output.txt; then
            echo "::error::Deployment would delete resources"
            exit 1
          fi

      - name: Validate Deployment
        run: |
          az deployment group validate \
            --resource-group rg-prod \
            --template-file ./main.bicep \
            --parameters @main.parameters.json

      - name: Check for Secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy Bicep
        run: |
          az deployment group create \
            --resource-group rg-prod \
            --template-file ./main.bicep \
            --parameters @main.parameters.json \
            --mode Incremental \
            --what-if-exclude-change-types Modify NoChange
```

```powershell
# Local pre-commit validation script
# .git/hooks/pre-commit

#!/bin/bash

echo "Running Bicep security validation..."

# Build all Bicep files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep '\.bicep$'); do
  echo "Validating $file..."
  
  # Bicep build
  az bicep build --file "$file" || exit 1
  
  # PSRule validation
  pwsh -Command "Assert-PSRule -Module PSRule.Rules.Azure -InputPath '$file' -Format File" || exit 1
done

# Check for secrets
git diff --cached | grep -E '(password|secret|key|token).*=.*["\x27]' && {
  echo "ERROR: Potential secret detected in commit"
  exit 1
}

echo "Security validation passed"
```

```bicep
// bicepconfig.json - Enable all analyzers
{
  "analyzers": {
    "core": {
      "enabled": true,
      "rules": {
        "no-hardcoded-env-urls": {
          "level": "error"
        },
        "no-unused-params": {
          "level": "warning"
        },
        "no-unused-vars": {
          "level": "warning"
        },
        "prefer-interpolation": {
          "level": "warning"
        },
        "secure-parameter-default": {
          "level": "error"
        },
        "simplify-interpolation": {
          "level": "warning"
        },
        "protect-commandtoexecute-secrets": {
          "level": "error"
        },
        "use-stable-vm-image": {
          "level": "warning"
        },
        "explicit-values-for-loc-params": {
          "level": "warning"
        },
        "no-deployments-resources": {
          "level": "warning"
        }
      }
    }
  },
  "experimentalFeaturesEnabled": {
    "userDefinedTypes": true,
    "extensibility": true
  }
}
```

**Don't**:
```yaml
# VULNERABLE: No security validation
name: Deploy Bicep

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Deploy
        run: |
          # VULNERABLE: No build, lint, or security scan
          az deployment group create \
            --template-file ./main.bicep \
            --parameters @main.parameters.json
          # Direct deployment without validation

# VULNERABLE: No what-if analysis
# VULNERABLE: No secret scanning
# VULNERABLE: No SARIF upload to Security tab
# VULNERABLE: No PSRule validation
# VULNERABLE: Auto-approve in CI/CD

- name: Deploy without approval
  run: |
    az deployment group create \
      --template-file ./main.bicep \
      --mode Complete  # DANGEROUS: Can delete resources
      # No manual approval step
```

```bicep
// VULNERABLE: Disabled analyzers
// bicepconfig.json
{
  "analyzers": {
    "core": {
      "enabled": false  // All security checks disabled
    }
  }
}
```

**Why**: Automated security validation catches misconfigurations before deployment, preventing security incidents in production. Bicep linter detects syntax errors, deprecated syntax, and security anti-patterns. PSRule provides comprehensive Azure security baseline checks against CIS benchmarks and Azure Security Benchmark. What-if analysis prevents unexpected resource deletions and modifications. Secret scanning prevents credential commits to version control. SARIF integration provides visibility in GitHub Security tab and enables security-focused code reviews. Missing validation allows vulnerable infrastructure to reach production.

**Refs**: Azure Bicep Best Practices, Microsoft Security DevOps, PSRule for Azure, NIST 800-53 SA-11, DevSecOps

---

## Additional Security Best Practices

### Use Deployment Stacks for Lifecycle Management

```bicep
// Deployment stack for resource lifecycle control
targetScope = 'resourceGroup'

resource deploymentStack 'Microsoft.Resources/deploymentStacks@2024-09-01' = {
  name: 'app-infrastructure-stack'
  properties: {
    actionOnUnmanage: {
      resources: 'delete'
      resourceGroups: 'delete'
    }
    denySettings: {
      mode: 'denyDelete'
      applyToChildScopes: true
      excludedPrincipals: [
        emergencyAccessGroupId
      ]
    }
  }
}
```

### Implement Resource Naming Conventions

```bicep
// Naming module with validation
@description('Generate resource names following conventions')
param environment string
param workload string
param region string

var namingConvention = {
  storageAccount: 'st${workload}${environment}${uniqueString(resourceGroup().id)}'
  keyVault: 'kv-${workload}-${environment}-${region}'
  sqlServer: 'sql-${workload}-${environment}-${region}'
  appService: 'app-${workload}-${environment}-${region}'
}
```

### Enable Microsoft Defender for Cloud

```bicep
// Enable Defender plans at subscription level
targetScope = 'subscription'

resource defenderForServers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2'
  }
}

resource defenderForStorage 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'StorageAccounts'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'DefenderForStorageV2'
  }
}

resource defenderForSQL 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'SqlServers'
  properties: {
    pricingTier: 'Standard'
  }
}
```

---

## Quick Reference

| Rule | Level | CWE/Standard |
|------|-------|--------------|
| Secure Parameter Handling | strict | CWE-798, CWE-532 |
| Key Vault Security Configuration | strict | CWE-311 |
| Storage Account Security | strict | CWE-319, CWE-311 |
| SQL Database Security | strict | CWE-306, CWE-284 |
| Network Security Groups | strict | CWE-284, CWE-923 |
| Managed Identity Usage | strict | CWE-798 |
| Resource Locks | strict | NIST CP-9 |
| Diagnostic Settings | strict | CWE-778 |
| Azure Policy Compliance | strict | NIST CM-7 |
| Module Security | strict | CWE-829 |
| Private Endpoints | strict | CWE-923 |
| Automated Security Validation | strict | NIST SA-11 |

## Summary

These 12 Azure Bicep security rules provide comprehensive coverage:

1. **Secure Parameter Handling** - Protect secrets with @secure() and Key Vault
2. **Key Vault Security** - RBAC, network restrictions, and audit logging
3. **Storage Account Security** - Encryption, private access, versioning
4. **SQL Database Security** - Azure AD authentication, TDE, private endpoints
5. **Network Security Groups** - Least privilege rules and flow logs
6. **Managed Identity Usage** - Eliminate connection strings and access keys
7. **Resource Locks** - Prevent accidental deletion of critical resources
8. **Diagnostic Settings** - Comprehensive logging for compliance and detection
9. **Azure Policy Compliance** - Enforce organizational standards
10. **Module Security** - Validated, versioned modules from trusted registries
11. **Private Endpoints** - Network isolation for PaaS services
12. **Automated Security Validation** - CI/CD pipeline security checks

Implementing these rules ensures Azure Bicep code follows security best practices and compliance requirements for cloud infrastructure deployment.
