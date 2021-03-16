<p align="right"><a href="https://nuid.io"><img src="https://nuid.io/svg/logo.svg" width="20%"></a></p>

# nuid.zk

Zero knowledge proofs for React Native projects. This branch provides the
`@nuid/zk-react-native` npm package, mirroring the interface to the `@nuid/zk`
npm package.

Github issues and other communications are warmly welcomed.
[dev@nuid.io](mailto:support@nuid.io)

## Clojure and ClojureScript

See the [main branch](https://github.com/NuID/zk/blob/master/README.md) for
clj/s installation and usage.

## JavaScript

### Installing into an existing react-native app

`react-native` doesn't have a perfect hardware interop, so you'll need
to do a few additional steps to get the `zk` package with dependant polyfills
installed correctly.

The following is from
[parshap/node-libs-react-native](https://github.com/parshap/node-libs-react-native) on
GitHub.

1. First you'll need to install a few dependencies:
   + Install the `@nuid/zk-react-native` package  instead of `@nuid/zk`. This is a
     react-native specific version of NuID's `zk` package (which has an
     identical JS interface to `@nuid/zk`).
   + You'll also need `react-native-randombytes` as a top-level dependency in
     your app so that react-native will link it correctly.
   + And finally, `node-libs-react-native` for shimming node dependencies in
     react-native which is necessary to support zk credential and proof
     generation.

```sh
$ yarn add @nuid/zk-react-native node-libs-react-native react-native-randombytes
# if RN < 0.60
$ react-native link react-native-randombytes
# else RN >= 0.60, instead do
$ cd iOS && pod install
```

2. Modify `metro.config.js` to add `extraNodeModules` configuration to wire up
   `node-libs-react-native` correctly:

```js
// metro.config.js
module.exports = {
  // ...
  resolver: {
    extraNodeModules: require('node-libs-react-native')
  }
};
```

3. Import `node-libs-react-native/globals` before you import `@nuid/zk-react-native`:

``` js
// index.js
// Add globals here (or anywhere _before_ importing @nuid/zk-react-native)
import 'node-libs-react-native/globals';
import { registerRootComponent } from 'expo';
import App from './src/app';
registerRootComponent(App);
```

### React Native usage:

```js
import Zk from '@nuid/zk-react-native';

// client context, sign up
let password = "high entropy ✅"
let verifiable = Zk.verifiableFromSecret(password);
// send to server to register with NuID Auth API

// client context, sign in
// get challenge from API for user credential, then
let proof = Zk.proofFromSecretAndChallenge(password, challenge);
// 
```


## Licensing

Apache v2.0 or MIT

## ⚠️  Disclaimer

This library is [property
tested](https://github.com/clojure/test.check#testcheck) to help verify
implementation, but has not yet been audited by an independent third party.
