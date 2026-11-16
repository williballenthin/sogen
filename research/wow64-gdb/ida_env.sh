unset VIRTUAL_ENV IDAPYTHON_VENV_EXECUTABLE PYTHONPATH
export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '/malware-extensions/.venv/bin' | paste -sd: -)
export IDAUSR=/tmp/upx32/idausr
export IDADIR="/Applications/IDA Professional 9.5.app/Contents/MacOS"
export IDAPYTHON_VENV_EXECUTABLE=/tmp/unimx/v/bin/python
export VIRTUAL_ENV=/tmp/unimx/v
export PATH=/tmp/unimx/v/bin:$PATH
export IDA_LICENSE=$(ls /tmp/upx32/idausr/*.hexlic)
export PYTHONPATH=/Users/user/code/hex-rays/malware-extensions/ida-unpacker-framework:/Users/user/code/hex-rays/malware-extensions/one-click-debugging
export MALWARE_SOGEN_ANALYZER=${SOGEN_ANALYZER:-/Users/user/code/sogen/.claude/worktree/wow64-gdb/build/rel/artifacts/analyzer}
export MALWARE_SOGEN_ROOT=${SOGEN_ROOT:-/tmp/wow64gdb/root}
