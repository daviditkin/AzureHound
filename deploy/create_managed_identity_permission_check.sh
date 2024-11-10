#!/bin/bash

# ================================================
# Azure Permissions and Roles Checker
# ================================================
# This script displays the necessary Azure RBAC and
# Azure AD roles required to create a User-Assigned
# Managed Identity and an App Registration. It also
# checks if the currently logged-in user has these
# roles assigned.
# ================================================

set -euo pipefail

# ---------------------------
# Configuration Variables
# ---------------------------

# Resource Group where the Managed Identity would be created
RESOURCE_GROUP="YourResourceGroupName"

# Location for the Managed Identity
LOCATION="eastus"

# Name of the User-Assigned Managed Identity
MANAGED_IDENTITY_NAME="azureHoundManagedIdentity"

# ---------------------------
# Function Definitions
# ---------------------------

# Function to check for required CLI tools
check_prerequisites() {
    echo "Checking prerequisites..."
    if ! command -v az &> /dev/null
    then
        echo "❌ Azure CLI (az) is not installed. Please install it before running this script."
        exit 1
    fi

    if ! command -v jq &> /dev/null
    then
        echo "❌ jq is not installed. Please install it to parse JSON outputs."
        exit 1
    fi

    echo "✅ All prerequisites met."
    echo ""
}

# Function to list required Azure RBAC roles
list_required_rbac_roles() {
    echo "========================================"
    echo "📌 Required Azure RBAC Roles:"
    echo "========================================"
    echo "1. **Contributor**"
    echo "   - **Purpose**: Allows full management of all Azure resources, including the creation of User-Assigned Managed Identities."
    echo ""
    echo "2. **User Access Administrator**"
    echo "   - **Purpose**: Enables the assignment of roles to users, groups, and service principals. Required to assign roles to the Managed Identity."
    echo ""
}

# Function to list required Azure AD roles
list_required_ad_roles() {
    echo "========================================"
    echo "📌 Required Azure AD Roles:"
    echo "========================================"
    echo "1. **Application Administrator**"
    echo "   - **Purpose**: Allows managing all aspects of app registrations and enterprise apps, including granting permissions."
    echo ""
    echo "2. **Privileged Role Administrator** *(Optional)*"
    echo "   - **Purpose**: Enables managing role assignments in Azure AD, including assigning administrative roles."
    echo ""
    echo "3. **Global Administrator** *(Alternative)*"
    echo "   - **Purpose**: Has access to all administrative features in Azure AD. If you are a Global Admin, you inherently have all necessary permissions."
    echo ""
}

# Function to check current user's Azure RBAC roles
check_current_user_rbac_roles() {
    echo "========================================"
    echo "🔍 Checking Current User's Azure RBAC Roles:"
    echo "========================================"
    echo "Fetching roles assigned to your user..."

    # Get the current user's Object ID
    CURRENT_USER_OBJECT_ID=$(az ad signed-in-user show --query objectId -o tsv)

    if [ -z "$CURRENT_USER_OBJECT_ID" ]; then
        echo "❌ Error: Could not retrieve the current user."
        exit 1
    fi

    # List all Azure RBAC roles assigned to the current user at the subscription level
    CURRENT_USER_ROLES=$(az role assignment list --assignee "$CURRENT_USER_OBJECT_ID" --scope "/subscriptions/$(az account show --query id -o tsv)" --query "[].roleDefinitionName" -o tsv | sort | uniq)

    if [ -z "$CURRENT_USER_ROLES" ]; then
        echo "❌ No Azure RBAC roles assigned to the current user at the subscription scope."
    else
        echo "✅ Azure RBAC roles assigned to the current user:"
        echo "$CURRENT_USER_ROLES" | while read -r role; do
            echo "   - $role"
        done
    fi
    echo ""
}

# Function to check if the user has specific Azure RBAC roles
check_specific_rbac_roles() {
    REQUIRED_ROLES=("Contributor" "User Access Administrator")
    echo "========================================"
    echo "🔍 Verifying Required Azure RBAC Roles for Current User:"
    echo "========================================"
    for ROLE in "${REQUIRED_ROLES[@]}"
    do
        HAS_ROLE=$(echo "$CURRENT_USER_ROLES" | grep -Fx "$ROLE" || true)
        if [ -n "$HAS_ROLE" ]; then
            echo "✔️  You have the **'$ROLE'** role."
        else
            echo "❌  You do NOT have the **'$ROLE'** role."
        fi
    done
    echo ""
}

# Function to get the Azure AD role template ID
get_azure_ad_role_id() {
    local ROLE_DISPLAY_NAME="$1"
    # Fetch the role ID from Azure AD
    ROLE_ID=$(az rest --method GET \
        --url "https://graph.microsoft.com/v1.0/directoryRoles" \
        --headers "Content-Type=application/json" \
        --query "value[?displayName=='$ROLE_DISPLAY_NAME'].id" -o tsv)

    echo "$ROLE_ID"
}

# Function to activate a directory role if it's not already active
activate_directory_role() {
    local ROLE_DISPLAY_NAME="$1"
    local ROLE_ID="$2"

    if [ -z "$ROLE_ID" ]; then
        echo "🔄 Activating Azure AD role: **$ROLE_DISPLAY_NAME**"
        
        # Get the role template ID
        ROLE_TEMPLATE_ID=$(az rest --method GET \
            --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates" \
            --headers "Content-Type=application/json" \
            --query "value[?displayName=='$ROLE_DISPLAY_NAME'].id" -o tsv)

        if [ -z "$ROLE_TEMPLATE_ID" ]; then
            echo "❌ Error: Role template for '$ROLE_DISPLAY_NAME' not found."
            exit 1
        fi

        # Activate the directory role
        az rest --method POST \
            --url "https://graph.microsoft.com/v1.0/directoryRoles" \
            --headers "Content-Type=application/json" \
            --body "{ \"roleTemplateId\": \"$ROLE_TEMPLATE_ID\" }" > /dev/null

        # Retrieve the role ID again
        ROLE_ID=$(az rest --method GET \
            --url "https://graph.microsoft.com/v1.0/directoryRoles" \
            --headers "Content-Type=application/json" \
            --query "value[?displayName=='$ROLE_DISPLAY_NAME'].id" -o tsv)

        if [ -z "$ROLE_ID" ]; then
            echo "❌ Error: Failed to activate role '$ROLE_DISPLAY_NAME'."
            exit 1
        fi

        echo "✅ Role '$ROLE_DISPLAY_NAME' activated successfully."
    else
        echo "✅ Role '$ROLE_DISPLAY_NAME' is already active."
    fi

    echo "$ROLE_ID"
}

# Function to check current user's Azure AD roles
check_current_user_ad_roles() {
    echo "========================================"
    echo "🔍 Checking Current User's Azure AD Roles:"
    echo "========================================"
    echo "Fetching Azure AD roles assigned to your user..."

    # Get user object ID
    USER_OBJECT_ID=$(az ad signed-in-user show --query objectId -o tsv)

    if [ -z "$USER_OBJECT_ID" ]; then
        echo "❌ Error: Could not retrieve the current user's Azure AD Object ID."
        exit 1
    fi

    # List directory roles the user is a member of
    AD_ROLES=$(az rest --method GET \
        --url "https://graph.microsoft.com/v1.0/users/$USER_OBJECT_ID/memberOf/microsoft.graph.directoryRole" \
        --headers "Content-Type=application/json" \
        --query "value[].displayName" -o tsv)

    if [ -z "$AD_ROLES" ]; then
        echo "❌ No Azure AD roles assigned to the current user."
    else
        echo "✅ Azure AD roles assigned to the current user:"
        echo "$AD_ROLES" | while read -r role; do
            echo "   - $role"
        done
    fi
    echo ""
}

# Function to check if the user has specific Azure AD roles
check_specific_ad_roles() {
    REQUIRED_AD_ROLES=("Application Administrator" "Privileged Role Administrator" "Global Administrator")
    echo "========================================"
    echo "🔍 Verifying Required Azure AD Roles for Current User:"
    echo "========================================"
    for AD_ROLE in "${REQUIRED_AD_ROLES[@]}"
    do
        HAS_AD_ROLE=$(echo "$AD_ROLES" | grep -Fx "$AD_ROLE" || true)
        if [ -n "$HAS_AD_ROLE" ]; then
            echo "✔️  You have the **'$AD_ROLE'** Azure AD role."
        else
            echo "❌  You do NOT have the **'$AD_ROLE'** Azure AD role."
        fi
    done
    echo ""
}

# ---------------------------
# Main Script Execution
# ---------------------------

# Check prerequisites
check_prerequisites

# List required roles
list_required_rbac_roles
list_required_ad_roles

# Check current user's Azure RBAC roles
check_current_user_rbac_roles

# Check if the user has the required Azure RBAC roles
check_specific_rbac_roles

# Check current user's Azure AD roles
check_current_user_ad_roles

# Check if the user has the required Azure AD roles
check_specific_ad_roles

echo "✅ Script execution completed."
