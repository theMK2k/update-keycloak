/**
 * Update Keycloak v1.0.4
 *
 * This tool updates an application client's permissions and roles in keycloak.
 * This way you can manage your permissions and roles in your code and update them from your shell and during CI/CD.
 *
 * Prerequisites:
 * - A service account with the realm-management/realm-admin role is created and the credentials are available
 * - a typescript file with the following structure is available:
 * export const permissions = { permissionA: 'permission-a', permissionB: 'permission-b', ... };
 * export const roles = { roleA: ['permission-a', 'permission-b'], roleB: ['permission-c', 'permission-d'], ... };
 */

import axios from "axios";
import qs from "qs";
import logger from "loglevel";

const doCommit = process.argv.find((arg) => arg.toLowerCase() === "--commit");
const ignoreWarnings = process.argv.find(
  (arg) => arg.toLowerCase() === "--ignore-warnings"
);

// #region Env-Vars
const LOG_LEVEL = process.env.LOG_LEVEL;
const PERMISSIONS_AND_ROLES_TS_LOCATION =
  process.env.PERMISSIONS_AND_ROLES_TS_LOCATION;
const LOGIN_BASE_URL = process.env.LOGIN_BASE_URL;
const ADMIN_BASE_URL = process.env.ADMIN_BASE_URL;
const SERVICE_ACCOUNT_CLIENT_ID = process.env.SERVICE_ACCOUNT_CLIENT_ID;
const SERVICE_ACCOUNT_CLIENT_SECRET = process.env.SERVICE_ACCOUNT_CLIENT_SECRET;
const APPLICATION_CLIENT_ID = process.env.APPLICATION_CLIENT_ID;

if (!PERMISSIONS_AND_ROLES_TS_LOCATION) {
  logger.error("PERMISSIONS_AND_ROLES_TS_LOCATION not set!");
  process.exit(1);
}
if (!LOGIN_BASE_URL) {
  logger.error("LOGIN_BASE_URL not set!");
  process.exit(1);
}

logger.info("Using LOGIN_BASE_URL:", LOGIN_BASE_URL);

if (!ADMIN_BASE_URL) {
  logger.error("ADMIN_BASE_URL not set!");
  process.exit(1);
}

logger.info("Using ADMIN_BASE_URL:", ADMIN_BASE_URL);

if (!SERVICE_ACCOUNT_CLIENT_ID) {
  logger.error("SERVICE_ACCOUNT_CLIENT_ID not set!");
  process.exit(1);
}

logger.info("Using SERVICE_ACCOUNT_CLIENT_ID:", SERVICE_ACCOUNT_CLIENT_ID);

if (!SERVICE_ACCOUNT_CLIENT_SECRET) {
  logger.error("SERVICE_ACCOUNT_CLIENT_SECRET not set!");
  process.exit(1);
}

if (!APPLICATION_CLIENT_ID) {
  logger.error("APPLICATION_CLIENT_ID not set!");
  process.exit(1);
}

logger.info("Using APPLICATION_CLIENT_ID:", APPLICATION_CLIENT_ID);

// #endregion Env-Vars

// main function
(async () => {
  logger.setLevel(<any>(LOG_LEVEL || "info"));

  logger.info("Update Keycloak v1.0.2, LOG_LEVEL:", logger.getLevel());

  if (!doCommit) {
    logger.info(
      "\nRunning in dry-run mode, no changes will be made! Use --commit to commit changes."
    );
  }

  try {
    logger.debug("Loading permissions and roles...");
    const { permissions: localPermissions, roles: localRoles } = await import(
      PERMISSIONS_AND_ROLES_TS_LOCATION
    );

    if (!localPermissions) {
      logger.error(
        `permissions not found in '${PERMISSIONS_AND_ROLES_TS_LOCATION}'!`
      );
      process.exit(1);
    }
    if (!localRoles) {
      logger.error(
        `roles not found in '${PERMISSIONS_AND_ROLES_TS_LOCATION}'!`
      );
      process.exit(1);
    }

    logger.debug(
      " ",
      Object.keys(localPermissions).length,
      "permissions and",
      Object.keys(localRoles).length,
      "roles loaded"
    );

    if (
      !checkLocalPermissionsAndRoles(localPermissions, localRoles) &&
      !ignoreWarnings
    ) {
      logger.error(
        "\nABORT due to warnings (see above), use --ignore-warnings to continue anyways"
      );
      process.exit(1);
    }

    // logger.debug('permissions and roles:', { permissions, roles });

    // Log into keycloak with our service account and store the token
    logger.debug("Logging into keycloak...");
    const tokenResponse = await axios({
      method: "post",
      url: `${LOGIN_BASE_URL}/protocol/openid-connect/token`,
      data: qs.stringify({
        grant_type: "client_credentials",
        client_id: SERVICE_ACCOUNT_CLIENT_ID,
        client_secret: SERVICE_ACCOUNT_CLIENT_SECRET,
      }),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    logger.debug("  OK");

    // logger.debug('tokenResponse.data:', tokenResponse.data);

    const accessToken = tokenResponse.data.access_token;

    // logger.debug('accessToken:', accessToken);

    // https://iam.dev.evaglobal.io/admin/realms/EVA/clients?first=0&max=101

    logger.debug("Loading client list...");
    const clientsResponse = await axios({
      method: "get",
      url: `${ADMIN_BASE_URL}/clients`,
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    // logger.debug('clientsResponse.data:', clientsResponse.data);

    logger.debug(
      `Searching for client with clientId='${APPLICATION_CLIENT_ID}'...`
    );
    const applicationClient = clientsResponse.data.find(
      (client: any) => client.clientId === APPLICATION_CLIENT_ID
    );

    if (!applicationClient) {
      logger.error(
        `Client with clientId='${APPLICATION_CLIENT_ID}' not found!`
      );
      process.exit(1);
    }

    const applicationClientId = applicationClient.id;
    logger.debug(`  found! id:`, applicationClientId);

    // create missing remote permissions and roles
    await processMissingPermissionsAndRoles(
      applicationClientId,
      accessToken,
      localPermissions,
      localRoles
    );

    // delete orphaned remote permissions and roles
    await processOrphanedPermissionsAndRoles(
      applicationClientId,
      accessToken,
      localPermissions,
      localRoles
    );

    // process roles, now that the items themselves are synched
    // roles should have associated permissions and/or roles (composite roles)
    await processLocalCompositeRoles(
      applicationClientId,
      accessToken,
      localPermissions,
      localRoles
    );
  } catch (error) {
    logger.error(error);
  }
})();

/**
 * Check if all locally defined permissions are covered by the local roles
 * Print a warning if a permission is not covered by a role
 * @param localPermissions
 * @param localRoles
 */
function checkLocalPermissionsAndRoles(
  localPermissions: Record<string, string>,
  localRoles: Record<string, any>
): Boolean {
  let isOK = true;
  Object.values(localPermissions).forEach((permission) => {
    if (
      !Object.values(localRoles).find((role: any) =>
        role.permissions.includes(permission)
      )
    ) {
      logger.warn(
        `\nWARNING: Permission '${permission}' is not covered by any role!`
      );
      isOK = false;
    }
  });

  return isOK;
}

/**
 * Identify permissions and roles that are locally available but missing remotely and create them
 * @param applicationClientId
 * @param accessToken
 * @param localPermissions
 * @param localRoles
 */
async function processMissingPermissionsAndRoles(
  applicationClientId,
  accessToken,
  localPermissions,
  localRoles
) {
  logger.debug("[processOrphanedPermissionsAndRoles] START");

  logger.debug(`Loading keycloak roles...`);
  const remoteItemsResponse = await axios({
    method: "get",
    url: `${ADMIN_BASE_URL}/clients/${applicationClientId}/roles`,
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const remoteItems = remoteItemsResponse.data;

  logger.debug("  found", remoteItems.length, "roles");

  logger.debug("\nProcessing missing remote permissions...");
  const permissionsToAdd = [];
  for (const permission of Object.values(localPermissions)) {
    const permissionName = `p:${permission}`;
    logger.debug(`  '${permission}' as '${permissionName}'...`);

    const remotePermission = remoteItems.find(
      (remoteItem: any) => remoteItem.name === permissionName
    );

    if (remotePermission) {
      logger.debug(`    permission already extists`);
      continue;
    }

    logger.debug(`    permission not found, adding to list`);

    permissionsToAdd.push({ name: permissionName });
  }

  logger.debug("\nProcessing missing remote roles...");
  const rolesToAdd = [];
  for (const role of Object.keys(localRoles)) {
    const roleName = `r:${role}`;
    logger.debug(`  '${role}' as '${roleName}'...`);

    const remoteRole = remoteItems.find(
      (remoteItem: any) => remoteItem.name === roleName
    );

    if (remoteRole) {
      logger.debug(`    role already exists`);
      continue;
    }

    logger.debug(`    role not found, adding to list`);

    rolesToAdd.push({ name: roleName });
  }

  logger.info("\npermissions to add:", permissionsToAdd.length);
  permissionsToAdd.forEach((permission) => logger.info(" ", permission.name));

  logger.info("\nroles to add:", rolesToAdd.length);
  rolesToAdd.forEach((role) => logger.info(" ", role.name));

  if (!doCommit) {
    return;
  }

  for (const item of [...permissionsToAdd, ...rolesToAdd]) {
    logger.debug(`  adding '${item.name}'...`);
    await axios({
      method: "post",
      url: `${ADMIN_BASE_URL}/clients/${applicationClientId}/roles`,
      data: item,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }
}

/**
 * Identify permissions and roles that are remotely available but missing locally and delete them
 * @param applicationClientId
 * @param accessToken
 * @param localPermissions
 * @param localRoles
 */
async function processOrphanedPermissionsAndRoles(
  applicationClientId,
  accessToken,
  localPermissions,
  localRoles
) {
  logger.debug("[processOrphanedPermissionsAndRoles] START");

  logger.debug(`\nLoading keycloak roles...`);
  const rolesResponse = await axios({
    method: "get",
    url: `${ADMIN_BASE_URL}/clients/${applicationClientId}/roles`,
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const rolesRemote = rolesResponse.data;

  logger.debug("  found", rolesRemote.length, "roles");

  const permissionsToRemove = [];

  logger.debug("\nProcessing orphaned remote permissions...");
  for (const roleRemote of rolesRemote) {
    if (!roleRemote.name.startsWith("p:")) {
      continue;
    }

    const role = roleRemote.name.replace("p:", "");
    logger.debug(`  '${roleRemote.name}' as '${role}'...`);

    if (
      Object.values(localPermissions).find((permission) => permission == role)
    ) {
      logger.debug(`    permisson found in local permissions, skipping...`);
      continue;
    }

    logger.debug(
      `    permission not found in local permissions, adding to list`
    );

    permissionsToRemove.push(roleRemote);
  }

  const rolesToRemove = [];

  logger.debug("\nProcessing orphaned remote roles...");
  for (const roleRemote of rolesRemote) {
    if (!roleRemote.name.startsWith("r:")) {
      continue;
    }

    const role = roleRemote.name.replace("r:", "");
    logger.debug(`  '${roleRemote.name}' as '${role}'...`);

    if (Object.keys(localRoles).find((r) => r == role)) {
      logger.debug(`    role found in local roles, skipping...`);
      continue;
    }

    logger.debug(`    role not found in local roles, adding to list`);

    rolesToRemove.push(roleRemote);
  }

  logger.info("\npermissions to remove:", permissionsToRemove.length);
  permissionsToRemove.forEach((permission) =>
    logger.info(" ", permission.name)
  );

  logger.info("\nroles to remove:", rolesToRemove.length);
  rolesToRemove.forEach((role) => logger.info(" ", role.name));

  if (!doCommit) {
    return;
  }

  for (const item of [...permissionsToRemove, ...rolesToRemove]) {
    logger.debug(`  deleting '${item.name}'...`);
    await axios({
      method: "delete",
      url: `${ADMIN_BASE_URL}/roles-by-id/${item.id}`,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }
}

/**
 * Processes composite roles defined locally (roles that have associated permissions and/or roles)
 * and ensures the same setup is available remotely.
 *
 * **Important**: call this function after everything else is synched with:
 * - processMissingPermissionsAndRoles
 * - processOrphanedPermissionsAndRoles
 * @param applicationClientId
 * @param accessToken
 * @param localPermissions
 * @param localRoles
 */
async function processLocalCompositeRoles(
  applicationClientId,
  accessToken,
  localPermissions,
  localRoles
) {
  logger.debug("\n[processLocalCompositeRoles] START");

  logger.debug(`\nLoading keycloak roles...`);
  const rolesResponse = await axios({
    method: "get",
    url: `${ADMIN_BASE_URL}/clients/${applicationClientId}/roles`,
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const rolesRemote = rolesResponse.data;

  logger.debug("  found", rolesRemote.length, "roles");

  logger.info();

  for (const roleKey of Object.keys(localRoles)) {
    const roleName = `r:${roleKey}`;
    const localRole = localRoles[roleKey];

    logger.debug(`localRole:`, localRole);

    logger.debug(
      `\nProcessing local composite role '${roleKey}' as '${roleName}' with`,
      localRole.roles?.length,
      `associated roles and`,
      localRole.permissions?.length,
      `associated permissions ...`
    );

    logger.debug(`localRole:`, localRole);

    const remoteRole = rolesRemote.find(
      (roleRemote: any) => roleRemote.name === roleName
    );

    if (!remoteRole) {
      if (doCommit) {
        logger.error(`FATAL! Remote role '${roleName}' not found!`);
        process.exit(1);
      }

      logger.info(`  remote role not found (this is fine in dry-run)`);
      continue;
    }

    logger.debug("  remote role found, id:", remoteRole.id);

    // https://iam.dev.evaglobal.io/admin/realms/EVA/roles-by-id/d8340323-afdb-4eac-b89d-81e435b0cc98/composites
    logger.debug(`  Loading remote role's composites...`);
    const remoteRoleComposites = (
      await axios({
        method: "get",
        url: `${ADMIN_BASE_URL}/roles-by-id/${remoteRole.id}/composites`,
        headers: { Authorization: `Bearer ${accessToken}` },
      })
    ).data;

    // logger.debug('remoteRoleComposites:', remoteRoleComposites)

    logger.debug("  found", remoteRoleComposites.length, "remote composites");

    const itemsToAdd = [];

    // match local permissions with remote associated permissions
    for (const localPermission of localRole.permissions) {
      const permissionName = `p:${localPermission}`;
      logger.debug(
        `    associated local permission '${localPermission}' as '${permissionName}'...`
      );

      const remoteAssociatedPermission = remoteRoleComposites.find(
        (remoteComposite: any) => remoteComposite.name === permissionName
      );

      if (remoteAssociatedPermission) {
        logger.debug(`      remote associated role found, skipping...`);
        continue;
      }

      logger.debug(`      remote associated role not found, adding...`);

      const remotePermission = rolesRemote.find(
        (roleRemote: any) => roleRemote.name === permissionName
      );

      if (!remotePermission) {
        if (doCommit) {
          logger.error(
            `FATAL! Remote permission '${permissionName}' not found!`
          );
          process.exit(1);
        }

        logger.info(
          `      remote permission not found (this is fine in dry-run)`
        );
        continue;
      }

      itemsToAdd.push({ id: remotePermission.id, name: remotePermission.name });
    }

    // match local associated roles with remote associated roles
    for (const localRoles of localRole.roles) {
      const roleName = `r:${localRoles}`;
      logger.debug(
        `    associated local role '${localRoles}' as '${roleName}'...`
      );

      const remoteAssociatedRole = remoteRoleComposites.find(
        (remoteComposite: any) => remoteComposite.name === roleName
      );

      if (remoteAssociatedRole) {
        logger.debug(`      remote associated role found, skipping...`);
        continue;
      }

      logger.debug(`      remote associated role not found, adding...`);

      const remoteRole = rolesRemote.find(
        (roleRemote: any) => roleRemote.name === roleName
      );

      if (!remoteRole) {
        logger.error(`FATAL! Remote permission '${roleName}' not found!`);
        process.exit(1);
      }

      itemsToAdd.push({ id: remoteRole.id, name: remoteRole.name });
    }

    if (itemsToAdd.length === 0) {
      logger.debug(`  no items to add`);
    } else {
      if (!doCommit) {
        logger.debug(`        SKIP (dry-run)`);
      } else {
        await axios({
          method: "post",
          url: `${ADMIN_BASE_URL}/roles-by-id/${remoteRole.id}/composites`,
          data: itemsToAdd,
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        logger.debug("        OK");
      }
    }

    const itemsToRemove = [];
    for (const remoteComposite of remoteRoleComposites) {
      const remoteCompositeName = remoteComposite.name;

      if (
        localRole.permissions.find(
          (permission) => `p:${permission}` === remoteCompositeName
        ) ||
        localRole.roles.find((role) => `r:${role}` === remoteCompositeName)
      ) {
        logger.debug(
          `    remote composite '${remoteCompositeName}' found locally, skipping...`
        );
        continue;
      }

      logger.debug(
        `    remote composite '${remoteCompositeName}' not found locally, removing...`
      );
      itemsToRemove.push(remoteComposite);
    }

    if (itemsToRemove.length === 0) {
      logger.debug(`  no items to remove`);
    } else {
      if (!doCommit) {
        logger.debug(`        SKIP (dry-run)`);
      } else {
        await axios({
          method: "delete",
          url: `${ADMIN_BASE_URL}/roles-by-id/${remoteRole.id}/composites`,
          data: itemsToRemove,
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        logger.debug("        OK");
      }
    }

    logger.info(
      `${roleName} composite items:`,
      itemsToAdd.length,
      "to add,",
      itemsToRemove.length,
      "to remove"
    );
  }
}
