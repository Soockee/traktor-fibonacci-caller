#!/bin/bash

echo "Starting InterceptorScript in WrapperScript"
cd /app/
python3 -u sniffing.py &
status=$?
if [ $status -ne 0 ]; then
    echo "Failed to start server process: $status"
    exit $status
fi

echo "Starting Server in WrapperScript"
dotnet /app/traktor-test-http-caller.dll &
status=$?
if [ $status -ne 0 ]; then
    echo "Failed to start server process: $status"
    exit $status
fi

while sleep 120; do
    echo "still running"
done