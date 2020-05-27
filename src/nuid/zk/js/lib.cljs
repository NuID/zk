(ns nuid.zk.js.lib
  (:require
   [clojure.set :as set]
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [clojure.walk :as walk]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.cryptography.hash.lib :as hash.lib]
   [nuid.cryptography.bn :as crypt.bn]
   [nuid.elliptic.curve :as curve]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.protocol :as protocol]))

(defn fqn
  [x]
  (if (or (keyword? x) (symbol? x))
    (if-let [ns (namespace x)]
      (str ns "/" (name x))
      (name x))
    x))

(def fqns
  (into
   (hash-set)
   (map fqn)
   (set/union
    curve/ids
    hash/algorithms
    hash.lib/string-normalization-forms
    zk/protocols)))

(def -postwalk->js fqn)

(defn ->js
  [spec data]
  (->>
   (s/unform spec data)
   (walk/postwalk -postwalk->js)
   (clj->js)))

(defn -postwalk->clj
  [x]
  (if (fqns x)
    (keyword x)
    x))

(defn ->clj
  [spec data]
  (->>
   (js->clj data :keywordize-keys true)
   (walk/postwalk -postwalk->clj)
   (s/conform spec)))

(defn default-challenge-parameters
  []
  {::zk/protocol  ::protocol/knizk
   ::knizk/curve  {::curve/id ::curve/secp256k1}
   ::knizk/hashfn (hash/default-parameters {::hash/algorithm ::hash.alg/sha256})
   ::knizk/keyfn  (hash/default-parameters {::hash/algorithm ::hash.alg/scrypt})
   ::knizk/nonce  (s/unform ::crypt.bn/nonce (gen/generate (s/gen ::crypt.bn/nonce)))})

(defn default-challenge
  []
  (->>
   (default-challenge-parameters)
   (s/conform ::zk/challenge)))

(defn tag-secret
  [{::zk/keys [protocol]} secret]
  (case protocol
    ::protocol/knizk {::knizk/secret secret}))

(def credential-keys
  (into
   (hash-set)
   (map fqn)
   #{::knizk/keyfn
     ::knizk/pub}))

(defn obj-credential-filter
  [_ k _]
  (credential-keys k))
