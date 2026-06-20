# DeskAccess Android

This is the Android client shell for opening `deskaccess://` invite links.

Current scope:

- Accepts invite deep links.
- Allows paste/check of invite links.
- Parses the current secure invite token format.
- Shows mode, protocol, port, expiry, and route type.
- Builds a debug APK in GitHub Actions.

Not included yet:

- The gomobile transport bridge for libp2p/Iroh tunneling.
- Launching Android RDP/VNC/SSH apps after a tunnel is opened.

Build locally:

```sh
cd android
gradle :app:assembleDebug
```

The APK is written to:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```
