# Update Keycloak

A CLI tool to keep your keycloak client's roles up-to-date.

Warning: highly opinionated.

This README will be enhanced later.

Necessary environment variables:

```text
LOG_LEVEL=<string, "DEBUG"|"INFO"|"WARN"|"ERROR">
PERMISSIONS_AND_ROLES_TS_LOCATION=<string, path to the file describing the roles>
LOGIN_BASE_URL=<string, "https://your.keycloak.instance/realms/YOURREALM">
ADMIN_BASE_URL=<string, "https://your.keycloak.instance/admin/realms/YOURREALM">
SERVICE_ACCOUNT_CLIENT_ID=<string, id of your service client>
SERVICE_ACCOUNT_CLIENT_SECRET=<string, secret of your service client>
APPLICATION_CLIENT_ID=<string, name of the client whose roles should be managed>
```

Accepted command line parameters:

| param             | description                                                                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| --commit          | use this parameter, so that actual write access to keycloak will be performed, else update-keycloak will do a dry-run                          |
| --ignore-warnings | use this parameter to have update-keycloak continue its operation even if plausibility checks in your permissions and roles configuration fail |
