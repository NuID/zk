(ns nuid.zk.lib
  (:require
   [clojure.set :as set]
   [clojure.spec.alpha :as s]
   [clojure.walk :as walk]
   [nuid.ident.cryptography :as ident.crypt]
   [nuid.ident.elliptic :as ident.elliptic]
   [nuid.ident.zk :as ident.zk]
   [nuid.lib :as lib]
   [nuid.spec.lib :as spec.lib]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.protocol :as protocol]))

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
   (mapcat spec.lib/keys-spec->keys)
   #{::knizk/credential}))

(def fqns
  (into
   (hash-set)
   (map lib/fqn)
   (set/union
    ident.elliptic/curve-ids
    ident.crypt/hash-algorithms
    ident.crypt/string-normalization-forms
    ident.zk/protocols)))

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
