#!/bin/bash

npm run build

if npm test; then
    npm publish
else
    echo "Can't publish to NPM, tests failed!"
    exit 1
fi
