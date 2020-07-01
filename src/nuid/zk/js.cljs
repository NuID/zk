(ns nuid.zk.js
  (:require
   [clojure.spec.alpha :as s]
   [goog.object :as obj]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.elliptic.curve.point :as point]
   [nuid.spec.lib :as spec.lib]
   [nuid.zk :as zk]
   [nuid.zk.js.lib :as js.lib]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.lib :as lib]
   [nuid.zk.protocol :as zk.protocol]))

(defn verifiableFromSecret
  [secret]
  (let [challenge  (lib/default-challenge)
        secret     (lib/tag-secret challenge secret)
        pub        (zk/pub (into challenge secret))
        proof      (zk/proof (merge challenge pub secret))
        verifiable (merge challenge pub proof)]
    (js.lib/->js ::zk/verifiable verifiable)))

(def -isVerified
  (comp
   (complement s/invalid?)
   (partial js.lib/->clj ::zk/verified)))

(defn isVerified
  [verifiable]
  (try
    (-isVerified verifiable)
    (catch :default _
      false)))

(defn -credential-filter
  [_ k _]
  (js.lib/credential-key? k))

(defn credentialFromVerifiable
  [verifiable]
  (let [filtered (obj/filter verifiable -credential-filter)
        values   (obj/getValues filtered)]
    (apply js/Object.assign values)))

(defn defaultChallengeFromCredential
  [credential]
  (let [credential (js.lib/->clj credential)
        pub        (spec.lib/select-keys ::point/parameters credential)
        keyfn      (->>
                    (hash.alg/parameters-multi-spec credential)
                    (spec.lib/keys-spec->keys)
                    (into #{::hash/algorithm})
                    (select-keys credential))
        challenge  (into
                    (knizk/default-challenge-parameters)
                    {::zk/protocol ::zk.protocol/knizk
                     ::knizk/pub   pub
                     ::knizk/keyfn keyfn})]
    (js.lib/->js ::zk/challenge challenge)))

(defn proofFromSecretAndChallenge
  [secret challenge]
  (let [challenge (js.lib/->clj ::zk/challenge challenge)
        secret    (lib/tag-secret challenge secret)
        proof     (zk/proof (into challenge secret))
        protocol  (::zk/protocol challenge)
        tagged    (assoc proof ::zk/protocol protocol)]
    (js.lib/->js ::zk/proof tagged)))

(defn verifiableFromProofAndChallenge
  [proof challenge]
  (js/Object.assign challenge proof))

(def exports
  #js {:verifiableFromSecret            verifiableFromSecret
       :isVerified                      isVerified
       :credentialFromVerifiable        credentialFromVerifiable
       :defaultChallengeFromCredential  defaultChallengeFromCredential
       :proofFromSecretAndChallenge     proofFromSecretAndChallenge
       :verifiableFromProofAndChallenge verifiableFromProofAndChallenge})
