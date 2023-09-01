# RBAC Package

A simple Role-Based Access Control (RBAC) system for managing roles and permissions for API resources.

## Overview

This package provides a straightforward implementation of RBAC. It 
enables you to specify roles, assign permissions to them for specific 
resources (e.g., API endpoints), and then check if a role has a certain 
permission for a given resource.

## Structure

- **Roles**: Represents the user or system component.
- **Resources**: Represents API endpoints or specific resources.
- **Permissions**: The operations (like GET, POST) that a role can perform on a resource.

## Usage

### Defining the Policy

A sample policy is represented in JSON format:

```json
{
  "roles": {
    "client1": {
      "permissions": {
        "/users": ["GET", "PUT", "POST", "DELETE"],
        "/products": ["GET", "PUT"]
      }
    },
    "client2": {
      "permissions": {
        "/users": ["GET"]
      }
    }
  }
}
```

### Loading the Policy

```go
data := []byte(yourPolicyJSON)
policy, err := rbac.LoadRBACPolicyFromBytes(data)
```

### Checking Permissions

To check if a role has permission for a specific operation on a resource:
```go
hasPermission, err := policy.CheckPermission("api1", "/users", "GET")
```
