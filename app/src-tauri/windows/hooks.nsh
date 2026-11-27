; Genra AV NSIS hooks (tauri.release.conf.json, bundle.windows.nsis.installerHooks).
; The app writes its Explorer menu entry itself (src/shell.rs); uninstalling removes it.
!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\GenraAV"
!macroend
