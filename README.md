# HelloID-Conn-Prov-Target-TripleEye

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://www.triple-eye.nl/resources/img/social.jpg">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-TripleEye](#helloid-conn-prov-target-tripleeye)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Invitation Code](#invitation-code)
    - [Allow External Management](#allow-external-management)
    - [Body Signature](#body-signature)
    - [Correlation Based on Email Address](#correlation-based-on-email-address)
    - [Name property](#name-property)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-TripleEye_ is a _target_ connector. _TripleEye_ provides a set of REST API's that allow you to programmatically interact with its data.

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks |
| ----------------------------------------- | --------- | --------------------------------------- | ------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |         |
| **Permissions AccessGroups**              | ✅         | Retrieve, Grant, Revoke                 |   |
| **Permissions Departments**               | ✅         | Retrieve, Grant, Revoke                 |   |
| **Resources**                             | ❌         | -                                       |         |
| **Entitlement Import: Accounts**          | ❌         | *No API endpoint available*             |         |
| **Entitlement Import: Permissions**       | ❌         | *No API endpoint available*             |         |
| **Governance Reconciliation Resolutions** | ❌         | -                                       |         |

## Getting started

### Prerequisites
- The credentials listed in the [Connection settings](#connection-settings).
- Resources, [Allow External Management](#allow-external-management).

### Connection settings

The following settings are required to connect to the API.

| Setting       | Description                             | Mandatory |
| ------------- | --------------------------------------- | --------- |
| HookId        | The HookId to connect to the API        | Yes       |
| Token         | The Token to connect to the API         | Yes       |
| SignatureCode | The SignatureCode to connect to the API | Yes       |
| BaseUrl       | The URL to the API                      | Yes       |

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _TripleEye_ to a person in _HelloID_.

| Setting                   | Value                                           |
| ------------------------- | ----------------------------------------------- |
| Enable correlation        | `True`                                          |
| Person correlation field  | `Person.Accounts.MicrosoftActiveDirectory.mail` |
| Account correlation field | `email`                                         |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the property `id` property from _TripleEye_.

## Remarks
### Invitation Code
The connector does not manage invitation codes. The application manager will send the invitation codes personally. The new employee will receive an email with a link to access the organization in the app on their phone.

### Allow External Management
Existing accounts or permissions that are required to be managed by HelloID must have "Allow external management" enabled; otherwise, the API cannot modify or access the resource.

### Body Signature
A signature is used to authenticate the request body, ensuring its integrity. Therefore, each web call requires a unique signature calculation. The current connector already handles this, but keep it in mind when adjusting the code.


### Correlation Based on Email Address
The connector relies on email addresses to correlate and match records between systems. Ensure that email addresses are accurately maintained and consistent across systems to avoid issues with data synchronization and matching.

### Name property
The `Name` property can only be 50 characters long. Characters beyond the 50th will be ignored. In the field mapping, there is a complex mapping that uses a Substring function to select only the first 50 characters. This is done to avoid continuous differences during update actions.

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint                                | Description                           |
| --------------------------------------- | ------------------------------------- |
| /organisation/employees/findOne         | Retrieve (single) user information    |
| /organisation/employees                 | Create and Update account information |
| /organisation/employees/<id>            | Delete user account                   |
| /organisation/accessGroups              | Retrieve access group information     |
| /organisation/linkAccessGroupEmployee   | Grant access group membership         |
| /organisation/unlinkAccessGroupEmployee | Revoke access group membership        |
| /organisation/departments               | Retrieve department information       |
| /organisation/linkDepartmentEmployee    | Grant department membership           |
| /organisation/unlinkDepartmentEmployee  | Revoke department membership          |

### API documentation
> [!NOTE]
> No Public API documentation is available.

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/5355-helloid-conn-prov-target-tripleeye)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
