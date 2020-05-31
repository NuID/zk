(ns nuid.zk.lib
  (:require
   [clojure.set :as set]
   [clojure.walk :as walk]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.cryptography.hash.lib :as hash.lib]
   [nuid.elliptic.curve :as curve]
   [nuid.lib :as lib]
   [nuid.spec :as spec]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.protocol :as protocol]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]])))

(defn default-challenge-parameters
  []
  (into
   {::zk/protocol ::protocol/knizk}
   (knizk/default-challenge-parameters)))

(defn default-challenge
  []
  (s/conform
   ::zk/challenge
   (default-challenge-parameters)))

(defn tag-secret
  [{:nuid.zk/keys [protocol]} secret]
  (case protocol
    ::protocol/knizk {::knizk/secret secret}))

(def credential-keys
  (into
   (hash-set)
   (mapcat spec/keys-spec->keys)
   [::knizk/credential]))

(def fqns
  (into
   (hash-set)
   (map lib/fqn)
   (set/union
    curve/ids
    hash.alg/algorithms
    hash.lib/string-normalization-forms
    protocol/protocols)))

(defn -postwalk-stringify
  [x]
  (if (or (keyword? x) (symbol? x))
    (lib/fqn x)
    x))

(defn -postwalk-keywordize
  [x]
  (if (fqns x)
    (keyword x)
    x))

(def stringify
  (partial walk/postwalk -postwalk-stringify))

(def keywordize
  (partial walk/postwalk -postwalk-keywordize))
