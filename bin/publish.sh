#!/bin/bash

out_file=target/react_native/nuid_zk.js
rm -rf target
shadow-cljs release react-native

contents=$(cat $out_file)
cat <<EOF > $out_file
// Solve 'brorand' dependency on (global.)self.crypto
import 'react-native-crypto'
self.crypto = window.crypto
// Original Build
${contents}
EOF

npm publish
