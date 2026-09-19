terraform {
  # 1.12 is the floor, not a preference: it is the first release where `||` short-circuits in a
  # variable validation block. Below it, the AVM modules' `var.x == null || var.x.y == ...` guards
  # still evaluate the right-hand side against null, and `terraform validate` fails with 11 errors
  # inside the vendored automation, dce and dcr modules before it ever reaches this configuration.
  required_version = ">= 1.12"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0, < 5.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.4"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # Remote state recommended; example:
  # backend "azurerm" {
  #   resource_group_name  = "rg-tfstate"
  #   storage_account_name = "sttfstate"
  #   container_name       = "tfstate"
  #   key                  = "btg-compliance.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  features {}
  subscription_id     = var.subscription_id
  storage_use_azuread = true
}

provider "azapi" {}

provider "azuread" {}
