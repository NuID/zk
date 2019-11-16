# nuid.zk

Cross-platform zero knowledge proofs.

## ⚠️  This library has not been independently audited.

Git issues and other communications are warmly welcomed. [dev@nuid.io](mailto:dev@nuid.io)

## Requirements

[`jvm`](https://www.java.com/en/download/), [`node + npm`](https://nodejs.org/en/download/), [`clj`](https://clojure.org/guides/getting_started), [`shadow-cljs`](https://shadow-cljs.github.io/docs/UsersGuide.html#_installation)

## From Clojure and ClojureScript

### tools.deps:

`{nuid/zk {:git/url "https://github.com/nuid/zk" :sha "..."}}`

### usage:

```
$ clj # or shadow-cljs node-repl
=> (require
     #?@(:clj
         ['[clojure.spec-alpha2.gen :as gen]
          '[clojure.spec-alpha2 :as s]]
         :cljs
         ['[clojure.spec.gen.alpha :as gen]
          '[clojure.test.check.generators]
          '[clojure.spec.alpha :as s]])
     '[nuid.cryptography :as crypt]
     '[nuid.zk :as zk])

=> (def parameters (gen/generate (s/gen ::zk/parameters)))
=> (def secret     "high entropy ✅")
=> (def pub        (zk/pub (assoc parameters :secret secret)))
=> (def nonce      (gen/generate (s/gen ::crypt/nonce)))
=> (def parameters (merge parameters {:pub pub :nonce nonce}))

=> (def good-proof (zk/proof (merge parameters {:secret secret})))
=> (def bad-proof  (zk/proof (merge parameters {:secret "garbage 🚮"})))

=> (zk/verified?   (merge parameters good-proof))
=> (zk/verified?   (merge parameters bad-proof))
```

## From JavaScript

### node:

```
$ node
> var Zk = require('@nuid/zk');

// client context, sign up
> var secret = "high entropy ✅"
> var proof = Zk.proofFromSecret(secret);
> var json = JSON.stringify(proof);

// server context, sign up
> var proof = JSON.parse(json);
> Zk.proofIsVerified(proof);
> var credential = Zk.credentialFromProof(proof); // persist (db, ledger, ...)

// server context, sign in
> var challenge = Zk.challengeFromCredential(credential);
> var json = JSON.stringify(challenge);

// client context, sign in
> var challenge = JSON.parse(json);
> proof = Zk.proofFromSecret(challenge, secret);
> var json = JSON.stringify(proof);

// server context, sign in
> var proof = JSON.parse(json);
> Zk.proofIsVerified(proof) ? /* ... */ : /* ... */ ;
```

### browser:

The `npm` package is browser compatible in Webpack-like workflows.

## From Java

To call `nuid.zk` from Java or other JVM languages, use one of the recommended interop strategies ([var/IFn](https://clojure.org/reference/java_interop#_calling_clojure_from_java) or [uberjar/aot](https://push-language.hampshire.edu/t/calling-clojure-code-from-java/865)). Doing so may require modifications or additions to the API for convenience.

## From CLR

[Coming soon](https://github.com/bcgit/bc-csharp)

## Notes

The purpose of `nuid.zk` and sibling `nuid` libraries (e.g. [`nuid.bn`](https://github.com/nuid/bn)) is to abstract over platform-specific differences and provide a common interface to fundamental dependencies. This allows us to express dependent logic (e.g. [`nuid.zk`](https://github.com/nuid/zk)) once in pure Clojure(Script), and use it from each of the host platforms (Java, JavaScript, CLR). This is particularly useful for generating and verifying proofs across service boundaries.

## Licensing

Apache v2.0 or MIT

## Contributing

### formatting:

```
$ clojure -A:cljfmt            # check
$ clojure -A:cljfmt:cljfmt/fix # fix
```

### dependencies:

```
## check
$ npm outdated
$ clojure -A:depot

## update
$ npm upgrade -s
$ clojure -A:depot:depot/update
```
