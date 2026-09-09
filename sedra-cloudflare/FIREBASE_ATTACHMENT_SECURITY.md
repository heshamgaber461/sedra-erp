# Secure CRM Attachment Permissions

This build changes CRM attachments so that:

- The uploader can always see their own attachment.
- Selected employees can see the attachment.
- Managers and Super Admins have automatic access.
- Other Sales employees do not receive the attachment.
- Firebase Realtime Database rules protect the attachment records server-side.
- The old `/.json` database read was removed from the app because a parent `.read` permission would bypass child-level attachment rules.

## Required Firebase step

The ZIP includes `database.rules.json`.

In Firebase Console:

1. Open project **sedra-crm**.
2. Go to **Realtime Database → Rules**.
3. Replace the current rules with the contents of `database.rules.json`.
4. Publish the rules.

The application will not have the new server-side protection until these rules are published.

## Existing attachments

On the first Super Admin refresh after publishing the rules, the app migrates access entries for existing attachments. Existing attachment `visibility` / `shareEmails` values are respected, and Managers/Super Admins are added to the access index.

## New attachments

When uploading an attachment, the CRM now shows a list of active employees. Select one or more people. The uploader plus Managers/Super Admins always receive access.
