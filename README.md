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
- `admin`: can do everything an editor can do, plus create user accounts at `users.php`.

The backend enforces these permissions. Frontend hiding of edit buttons is only a convenience; it is not the security boundary.

The application entry point is `index.php`. There is no separate `index.html` copy, so Apache/XAMPP should serve the PHP app.

Sessions use a browser-session cookie and a 30-minute server-side idle timeout. Closing the browser should drop the session cookie; idle sessions are rejected on the next page or API request.

## CSRF protection

State-changing requests are protected with a per-session CSRF token stored in the PHP session.

Protected routes/endpoints:

- `login.php`
- `change-password.php`
- `users.php`
- `logout.php`
- `api/save-device.php`

PHP forms include the token as a hidden `csrf_token` field. The authenticated device-save request sends the same token in the `X-CSRF-Token` header. Missing or invalid tokens are rejected server-side; frontend checks are only for transport and readable errors.

Session cookies use `HttpOnly` and `SameSite=Lax`. On HTTPS deployments PHP will mark the session cookie `Secure`; for production beyond a trusted LAN, use HTTPS.

## Password policy

All new or changed passwords must have:

- at least 12 characters
- at least one uppercase letter
- at least one lowercase letter
- at least one number

The bootstrap `admin/admin` password is the only temporary exception and is forced to change on first login.

## Shared data files

- `data/devices.json` is the server-side source of truth.
- `data/backups/` receives a uniquely named timestamped JSON backup before every successful save attempt.
- `data/devices.json.lock` is used by PHP as the device write lock file.
- `data/users.json` stores user accounts and password hashes.
- `data/users.json.lock` is used by PHP as the user write lock file.
- Browser `localStorage` is not used as authoritative persistence.

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

Editable fields are limited to `hostname`, `type`, `vendor`, `comment`, `mac`, and `warn`.

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
- `data/backups/`

The exact owner/group depends on the Apache user, commonly `www-data` on Debian/Ubuntu or `apache` on RHEL-like systems.

## Quick verification

1. Open `http://localhost/Topologie_Site/`; unauthenticated users should see only login/change-password pages.
2. Login as `admin/admin`; you should be forced to change the password.
3. Create a `viewer`, `editor`, and/or `admin` from `users.php` after changing the admin password.
4. Confirm viewers can browse/export but cannot see edit buttons.
5. Confirm editors/admins can edit device metadata.
6. Confirm a new file appears in `data/backups/` after saving a device.
7. Try opening `http://localhost/Topologie_Site/data/devices.json`; it should be blocked if `.htaccess` overrides are active.