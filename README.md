# Topologie Site

Plain HTML/CSS/JS network topology tool with a small PHP/JSON persistence layer and minimal PHP session authentication.

## Local XAMPP run

1. Place this folder at `C:\xampp\htdocs\Topologie_Site\`.
2. Start Apache in XAMPP.
3. Open `http://localhost/Topologie_Site/`.
4. Login with the bootstrap admin account:
   - username: `admin`
   - temporary password: `admin`
5. Change the temporary password before using the app.

## Authentication and roles

Users are stored in `data/users.json`. Passwords are stored with PHP `password_hash`; plaintext passwords are not stored.

Roles:

- `viewer`: can browse, filter, sort, and export CSV.
- `editor`: can do everything a viewer can do, plus edit device metadata.
- `admin`: can do everything an editor can do, plus manage user accounts and perform cleanup at `users.php`.

The backend enforces these permissions. Frontend hiding of edit buttons is only a convenience; it is not the security boundary.

The application entry point is `index.php`. There is no separate `index.html` copy, so Apache/XAMPP should serve the PHP app.

Sessions use a browser-session cookie and a 5-minute server-side idle timeout. Closing the browser should drop the session cookie; idle sessions are rejected on the next page or API request. Normal pages redirect to `login.php`; API endpoints return JSON with `error.code = "session_expired"` when the idle timeout is hit.

Authenticated pages also load a best-effort `navigator.sendBeacon` logout helper on page close. Browser unload events are not guaranteed and can fire differently across browsers, so this is only cleanup. The real protection is still the browser-session cookie, full server-side logout, and the 5-minute inactivity timeout.

## CSRF protection

State-changing requests are protected with a per-session CSRF token stored in the PHP session.

Protected routes/endpoints:

- `login.php`
- `change-password.php`
- `users.php`
- `logout.php`
- `api/save-device.php`
- `api/rollback-device.php`
- `api/sync-topology.php`

PHP forms include the token as a hidden `csrf_token` field. The authenticated device-save request sends the same token in the `X-CSRF-Token` header. Missing or invalid tokens are rejected server-side; frontend checks are only for transport and readable errors.

Session cookies use `HttpOnly` and `SameSite=Lax`. On HTTPS deployments PHP will mark the session cookie `Secure`; for production beyond a trusted LAN, use HTTPS.

## Password policy

All new or changed passwords must have:

- at least 12 characters
- at least one uppercase letter
- at least one lowercase letter
- at least one number

The bootstrap `admin/admin` password is the only temporary exception and is forced to change on first login.

Password changes also enforce history:

- the new password cannot equal the current password
- the new password cannot reuse any of the last 3 previous passwords
- password history stores only password hashes, never plaintext
- the same rule is enforced for first-login changes, normal password changes, and admin password resets

## Account lifecycle

Admins can disable, enable, reset passwords, force password change for non-admin users, and delete users from `users.php`.

Disable/delete rules:

- disabled users cannot log in
- users must be disabled before deletion
- admins can reset passwords for disabled users, including disabled admins
- password resets mark the account to require a password change on next login
- an admin cannot disable or delete their own currently logged-in account
- the app blocks disabling the last enabled admin
- the app blocks deleting the last remaining admin

Recovery workflow:

1. Disable the account to stop login.
2. Reset the password while the account is disabled.
3. Enable the account when the recovered user should log in and change the reset password.
4. Disable again before deletion if the account is being cleaned up.

## Audit trail and history

Manual action history is stored in append-only newline-delimited JSON at `data/audit.log`. Each line is one structured audit event. The app writes this file only from trusted PHP backend paths; frontend requests cannot submit their own audit payloads.

Each audit event includes:

- unique `id`
- `timestamp`
- `actor.username` and `actor.role`
- `eventType`
- `target.type`
- `target.identifier`
- changed fields with `old` and `new` values when applicable
- short `summary`

The current stable device identifier is the device `ip` field. There is no separate internal device id yet, so device audit and rollback target `target.type = "device"` with `target.identifier` equal to the IP address. If device IPs are later allowed to change, add an internal immutable id before relying on long-term device history across IP changes.

Implemented audit event types:

- `device_update`
- `device_rollback`
- `user_create`
- `user_disable`
- `user_enable`
- `user_password_reset`
- `user_force_password_change`
- `user_delete`
- `password_change_self`
- `login_success`
- `logout`

Passwords are never written to the audit log. Password changes and resets record the event and safe account flags only, not plaintext passwords or password hashes.

Device history is available from `api/device-history.php?ip=<device-ip>` and appears in the existing device modal. Admins can trigger field-aware device rollback from that modal. Rollback applies only the editable fields recorded in the selected audit event and writes a new `device_rollback` audit event; it does not restore whole backup files.

Recent account/admin history is available to admins from `api/user-history.php` and is shown at the bottom of `users.php`.

## Shared data files

- `data/devices.json` is the accepted combined topology snapshot after sync. It is not treated as "MikroTik truth" or "nmap truth".
- `data/backups/` receives a uniquely named timestamped JSON backup before every successful save attempt.
- `data/devices.json.lock` is used by PHP as the device write lock file.
- `data/users.json` stores user accounts and password hashes.
- `data/users.json.lock` is used by PHP as the user write lock file.
- `data/audit.log` stores append-only audit events as newline-delimited JSON.
- `data/audit.log.lock` is used by PHP as the audit write lock file.
- Browser `localStorage` is not used as authoritative persistence.

## Topology refresh package

Topology refresh builds one combined candidate topology from:

- `data/imports/mikrotik-leases.raw`
- `data/imports/mikrotik-leases.json`
- `data/imports/nmap-scan.xml`

The candidate is merged from both sources together and compared against `data/devices.json`. Sync writes that combined candidate back into `data/devices.json` as the next accepted snapshot.

Raw MikroTik DHCP lease export is not consumed directly by the app. It should first be converted into the JSON import file with:

```bash
php tools/parse-mikrotik-leases.php
```

Default parser paths:

- raw input: `data/imports/mikrotik-leases.raw`
- JSON output: `data/imports/mikrotik-leases.json`

The parser writes the JSON through a temp file, verifies it, and only then atomically replaces `mikrotik-leases.json`. This makes it suitable for later cron/systemd automation on the server after the raw MikroTik export step completes.

Manual fields are preserved during candidate build and sync:

- `hostname`
- `comment`
- `type`
- `vendor`
- `warn`

Sync-managed fields currently come from the combined refresh package:

- `mac`
- `online`
- `rtt`

The UI also reports package freshness and source alignment. Recommended thresholds:

- max source age: `35` minutes
- max timestamp gap between MikroTik and nmap files: `5` minutes

Package status rules:

- `missing`: either source file is missing
- `stale`: either source file is older than 35 minutes
- `out_of_sync`: both sources exist and are fresh, but their timestamps differ by more than 5 minutes
- `ok`: both sources exist, both are fresh, and the timestamp gap is within 5 minutes

In practice, MikroTik and nmap should be refreshed together before review/sync so the candidate topology represents one coherent refresh package.

## Save safety

`api/save-device.php` uses this write flow:

1. Require an authenticated `editor` or `admin` session.
2. Acquire an exclusive lock on `data/devices.json.lock`.
3. Read and validate `data/devices.json`.
4. Validate edited fields from the request.
5. Write a backup into `data/backups/`.
6. Write updated JSON to a temporary file in `data/`.
7. Read the temp file back and verify it is valid JSON.
8. Atomically replace `data/devices.json` with the temp file.
9. Append a `device_update` audit event with changed fields only.

Editable fields are limited to `hostname`, `type`, `vendor`, `comment`, `mac`, and `warn`.

Device rollback uses the same lock/temp-file/atomic-replace style. It is admin-only and can roll back `hostname`, `type`, `vendor`, `comment`, `mac`, and `warn` values from a selected `device_update` or `device_rollback` audit event. It does not roll back account events, login/logout events, scanned online state, RTT, backups, or deleted users.

## Blocking direct data access

`.htaccess` files are included in `data/` and `data/backups/` to deny direct browser access when Apache allows overrides.

For Linux/Apache production, prefer a vhost/directory rule as well, because `.htaccess` only works when `AllowOverride` permits it. Example:

```apache
<Directory "/var/www/html/Topologie_Site/data">
    Require all denied
</Directory>
```

The PHP app can still read/write these files because filesystem access is separate from browser URL access.

## Linux/Apache deployment notes

For a later Apache deployment such as `http://10.77.77.69/Topologie_Site/`, keep paths relative as they are now and make sure Apache/PHP can write to:

- `data/devices.json`
- `data/devices.json.lock`
- `data/users.json`
- `data/users.json.lock`
- `data/audit.log`
- `data/audit.log.lock`
- `data/backups/`

The exact owner/group depends on the Apache user, commonly `www-data` on Debian/Ubuntu or `apache` on RHEL-like systems.

## Quick verification

1. Open `http://localhost/Topologie_Site/`; unauthenticated users should see only login/change-password pages.
2. Login as `admin/admin`; you should be forced to change the password.
3. Create a `viewer`, `editor`, and/or `admin` from `users.php` after changing the admin password.
4. Confirm viewers can browse/export but cannot see edit buttons.
5. Confirm editors/admins can edit device metadata.
6. Confirm a new file appears in `data/backups/` after saving a device.
7. Reopen the device modal and confirm recent device history appears.
8. As admin, roll back a recent device update and confirm a new rollback history entry appears.
9. Open `users.php` and confirm recent account history appears.
10. Try opening `http://localhost/Topologie_Site/data/devices.json`; it should be blocked if `.htaccess` overrides are active.
