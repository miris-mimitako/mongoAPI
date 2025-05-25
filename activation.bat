@echo off
set "VENV_BASE_DIR=C:\applications\create_rag"  
set "VENV_NAME=venv"                                     

if exist "%VENV_BASE_DIR%\%VENV_NAME%\Scripts\activate.bat" (
    call "%VENV_BASE_DIR%\%VENV_NAME%\Scripts\activate.bat"
    echo %VENV_NAME%をアクティベートしました。
) else (
    echo エラー: 指定されたパスにvenvが見つからないか、activate.batが存在しません。
    echo 設定を確認してください:
    echo VENV_BASE_DIR: %VENV_BASE_DIR%
    echo VENV_NAME: %VENV_NAME%
)
pause