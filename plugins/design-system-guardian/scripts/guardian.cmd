@echo off
>&2 echo Design System Guardian blocked: no host-pinned interpreter is enrolled.
>&2 echo Invoke guardian.py only through the protected host or CI runtime documented by this plugin.
exit /b 4
