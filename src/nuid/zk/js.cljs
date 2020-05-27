(ns nuid.zk.js
  (:require
   [clojure.spec.alpha :as s]
   [goog.object :as obj]
   [nuid.zk :as zk]
   [nuid.zk.js.lib :as lib]))

(defn proofFromSecret
  ([secret]
   (let [challenge  (lib/default-challenge)
         secret     (lib/tag-secret challenge secret)
         pub        (zk/pub (into challenge secret))
         proof      (zk/proof (merge challenge pub secret))
         verifiable (merge challenge pub proof)]
     (lib/->js ::zk/verifiable verifiable)))
  ([challenge secret]
   (let [challenge  (lib/->clj ::zk/challenge challenge)
         secret     (lib/tag-secret challenge secret)
         proof      (zk/proof (into challenge secret))
         verifiable (into challenge proof)]
     (lib/->js ::zk/verifiable verifiable))))

(def proofIsVerified
  (comp
   (complement s/invalid?)
   (partial lib/->clj ::zk/verified)))

(defn credentialFromProof
  [proof]
  (obj/filter proof lib/obj-credential-filter))

(defn challengeFromCredential
  [credential]
  (let [challenge (lib/default-challenge-parameters)]
    (->
     (lib/->js ::zk/challenge challenge)
     (js/Object.assign credential))))

(def exports
  #js {:proofFromSecret         proofFromSecret
       :proofIsVerified         proofIsVerified
       :credentialFromProof     credentialFromProof
       :challengeFromCredential challengeFromCredential})
