Unicode true
!include "MUI2.nsh"

!ifndef PROJECT_ROOT
  !error "Pass -DPROJECT_ROOT=<absolute path> to makensis"
!endif
!ifndef OUTPUT_EXE
  !error "Pass -DOUTPUT_EXE=<absolute path> to makensis"
!endif

Name "Galeikan 0.1.0 Preview"
OutFile "${OUTPUT_EXE}"
InstallDir "$LOCALAPPDATA\Programs\Galeikan"
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define MUI_ICON "assets/galeikan.ico"
!define MUI_UNICON "assets/galeikan.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets/header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets/welcome.bmp"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Galeikan CLI" SEC_CLI
  SetOutPath "$INSTDIR"
  File /oname=galeikan.exe "${PROJECT_ROOT}/target/release/galeikan.exe"
  File /oname=README.md "${PROJECT_ROOT}/packaging/README.md"
  SetOutPath "$INSTDIR\docs"
  File "${PROJECT_ROOT}/packaging/docs/*.md"
  SetOutPath "$INSTDIR\examples"
  File /r /x "__pycache__" /x "*.pyc" "${PROJECT_ROOT}/examples/*"
  SetOutPath "$INSTDIR\python"
  File "${PROJECT_ROOT}/python/pyproject.toml"
  SetOutPath "$INSTDIR\python\galeikan_bridge"
  File "${PROJECT_ROOT}/python/galeikan_bridge/__init__.py"
  File "${PROJECT_ROOT}/python/galeikan_bridge/_runner.py"
  SetOutPath "$INSTDIR\icons"
  File /oname=galeikan.ico "${PROJECT_ROOT}/packaging/windows/assets/galeikan.ico"
  SetOutPath "$INSTDIR\brand"
  File "${PROJECT_ROOT}/logo_GaleikanEcosystem.jpg"
  SetOutPath "$INSTDIR\editor\vscode"
  File /r "${PROJECT_ROOT}/editors/vscode/galeikan/*"
  SetOutPath "$INSTDIR\editor"
  File "${PROJECT_ROOT}/dist/galeikan-language-0.1.0.vsix"

  WriteRegStr HKCU "Software\Classes\Galeikan.Lang" "" "Galeikan source (.gak)"
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\DefaultIcon" "" "$INSTDIR\icons\galeikan.ico"
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\shell\open\command" "" 'notepad.exe "%1"'
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\shell\run" "" "Run with Galeikan"
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\shell\run\command" "" '"$INSTDIR\galeikan.exe" run "%1"'
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\shell\compile" "" "Compile with Galeikan"
  WriteRegStr HKCU "Software\Classes\Galeikan.Lang\shell\compile\command" "" '"$INSTDIR\galeikan.exe" compile "%1"'
  WriteRegStr HKCU "Software\Classes\.gak\OpenWithProgids" "Galeikan.Lang" ""
  StrCpy $0 ""
  ReadRegStr $0 HKCU "Software\Classes\.gak" ""
  StrCmp $0 "" 0 gak_association_done
    WriteRegStr HKCU "Software\Classes\.gak" "" "Galeikan.Lang"
    WriteRegDWORD HKCU "Software\Galeikan\Associations" ".gak" 1
  gak_association_done:

  WriteRegStr HKCU "Software\Classes\Galeikan.Script" "" "Galeikan source (.gaks)"
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\DefaultIcon" "" "$INSTDIR\icons\galeikan.ico"
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\shell\open\command" "" 'notepad.exe "%1"'
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\shell\run" "" "Run with Galeikan"
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\shell\run\command" "" '"$INSTDIR\galeikan.exe" run "%1"'
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\shell\compile" "" "Compile with Galeikan"
  WriteRegStr HKCU "Software\Classes\Galeikan.Script\shell\compile\command" "" '"$INSTDIR\galeikan.exe" compile "%1"'
  WriteRegStr HKCU "Software\Classes\.gaks\OpenWithProgids" "Galeikan.Script" ""
  StrCpy $0 ""
  ReadRegStr $0 HKCU "Software\Classes\.gaks" ""
  StrCmp $0 "" 0 gaks_association_done
    WriteRegStr HKCU "Software\Classes\.gaks" "" "Galeikan.Script"
    WriteRegDWORD HKCU "Software\Galeikan\Associations" ".gaks" 1
  gaks_association_done:
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "DisplayName" "Galeikan 0.1.0 Preview"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "DisplayIcon" "$INSTDIR\icons\galeikan.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetOutPath "$TEMP"
  Delete "$INSTDIR\galeikan.exe"
  Delete "$INSTDIR\README.md"
  RMDir /r "$INSTDIR\docs"
  RMDir /r "$INSTDIR\examples"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\icons"
  RMDir /r "$INSTDIR\brand"
  RMDir /r "$INSTDIR\editor"
  ClearErrors
  Delete "$INSTDIR\Uninstall.exe"
  IfErrors retry_self_delete self_delete_done
  retry_self_delete:
    Sleep 300
    Delete "$INSTDIR\Uninstall.exe"
  self_delete_done:
  RMDir "$INSTDIR"
  StrCpy $1 0
  ReadRegDWORD $1 HKCU "Software\Galeikan\Associations" ".gak"
  StrCmp $1 1 0 gak_cleanup_done
    StrCpy $0 ""
    ReadRegStr $0 HKCU "Software\Classes\.gak" ""
    StrCmp $0 "Galeikan.Lang" 0 +2
      DeleteRegValue HKCU "Software\Classes\.gak" ""
    DeleteRegValue HKCU "Software\Galeikan\Associations" ".gak"
  gak_cleanup_done:
  StrCpy $1 0
  ReadRegDWORD $1 HKCU "Software\Galeikan\Associations" ".gaks"
  StrCmp $1 1 0 gaks_cleanup_done
    StrCpy $0 ""
    ReadRegStr $0 HKCU "Software\Classes\.gaks" ""
    StrCmp $0 "Galeikan.Script" 0 +2
      DeleteRegValue HKCU "Software\Classes\.gaks" ""
    DeleteRegValue HKCU "Software\Galeikan\Associations" ".gaks"
  gaks_cleanup_done:
  DeleteRegValue HKCU "Software\Classes\.gak\OpenWithProgids" "Galeikan.Lang"
  DeleteRegValue HKCU "Software\Classes\.gaks\OpenWithProgids" "Galeikan.Script"
  DeleteRegKey /ifempty HKCU "Software\Classes\.gak\OpenWithProgids"
  DeleteRegKey /ifempty HKCU "Software\Classes\.gaks\OpenWithProgids"
  DeleteRegKey /ifempty HKCU "Software\Classes\.gak"
  DeleteRegKey /ifempty HKCU "Software\Classes\.gaks"
  DeleteRegKey HKCU "Software\Classes\Galeikan.Lang"
  DeleteRegKey HKCU "Software\Classes\Galeikan.Script"
  DeleteRegKey /ifempty HKCU "Software\Galeikan\Associations"
  DeleteRegKey /ifempty HKCU "Software\Galeikan"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Galeikan"
SectionEnd
