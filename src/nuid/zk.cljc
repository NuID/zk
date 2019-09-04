(ns nuid.zk
  (:require
   [nuid.elliptic.curve.point :as point]
   [nuid.elliptic.curve :as curve]
   [nuid.cryptography :as crypt]
   [nuid.base64 :as base64]
   [nuid.bn :as bn]
   #?@(:cljs [[goog.object :as obj]])))

(def dispatch (comp :id :protocol))

(defmulti pub dispatch)
(defmethod pub "knizk"
  [{:keys [curve keyfn secret]}]
  (point/mul (curve/base curve) (keyfn secret)))

(defmulti proof dispatch)
(defmethod proof "knizk"
  [{:keys [curve keyfn hashfn pub secret nonce]}]
  (let [q (curve/order curve)
        r (crypt/secure-random-bn-lt 32 q)
        A (point/mul (curve/base curve) r)
        c (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))
        x (keyfn secret)
        s (bn/mod (bn/add (bn/mul c x) r) q)]
    {:c c :s s}))

(defmulti verified? dispatch)
(defmethod verified? "knizk"
  [{:keys [curve hashfn pub nonce c s]}]
  (let [A (point/add (point/mul (curve/base curve) s)
                     (point/neg (point/mul pub c)))
        H (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))]
    (bn/eq? H c)))

(defn coerce
  "Coerces data into representations used by `nuid.zk` fns"
  [{:keys [pub curve keyfn hashfn] :as opts}]
  (merge opts {:hashfn (comp bn/from :digest (crypt/hashfn hashfn))
               :keyfn (comp bn/from :digest (crypt/hashfn keyfn))
               :curve (curve/from (or (:id curve) pub))}))

#?(:cljs
   (def exports
     (letfn [(generateScryptParameters
               [& [params]]
               (doto (clj->js (crypt/scrypt-parameters {:n 8192 :r 4}))
                 (obj/extend (or params #js {}))))

             (generateSpec
              [& [spec]]
              (doto #js {"protocol" #js {"id" "knizk"}
                         "curve" #js {"id" "secp256k1"}
                         "keyfn" (generateScryptParameters)
                         "hashfn" #js {"id" "sha256"
                                       "normalization-form" "NFKC"}}
                (obj/extend (or spec #js {}))))

             (coerceSpec
              [spec]
              (-> (generateSpec spec)
                  (js->clj :keywordize-keys true)
                  (coerce)))

             (generatePub
              ([secret] (generatePub nil secret))
              ([spec secret]
               (-> (merge
                    (coerceSpec spec)
                    {:secret secret})
                   (pub)
                   (point/rep)
                   (clj->js))))

             (coercePub
              [pub]
              (point/from-rep
               (js->clj pub)))

             (generateNonce
              [& [num-bytes]]
              (-> (or num-bytes 32)
                  (crypt/secure-random-bn)
                  (bn/str 16)))

             (coerceBn
              [hex]
              (bn/from hex 16))

             (generateProof
              [spec pub nonce secret]
              (-> (merge
                   (coerceSpec spec)
                   {:pub (coercePub pub)
                    :nonce (coerceBn nonce)
                    :secret secret})
                  (proof)
                  (update :c #(bn/str % 16))
                  (update :s #(bn/str % 16))
                  (clj->js)))

             (proofFromSecret
              ([secret] (proofFromSecret nil secret))
              ([spec secret]
               (let [spec (generateSpec spec)
                     pub (or (obj/get spec "pub") (generatePub spec secret))
                     nonce (or (obj/get spec "nonce") (generateNonce))
                     proof (generateProof spec pub nonce secret)]
                 (doto #js {"nonce" nonce "pub" pub}
                   (obj/extend spec proof)))))

             (coerceProof
              [proof]
              (merge
               (coerceSpec proof)
               {:pub (coercePub (obj/get proof "pub"))
                :nonce (coerceBn (obj/get proof "nonce"))
                :c (coerceBn (obj/get proof "c"))
                :s (coerceBn (obj/get proof "s"))}))

             (proofIsVerified
              [proof]
              (verified? (coerceProof proof)))

             (isCredentialKey
              [k]
              (#{"keyfn" "pub"} k))

             (credentialFromProof
              [proof]
              (obj/filter
               proof
               (fn [_ k _]
                 (isCredentialKey k))))

             (challengeFromCredential
              [cred]
              (doto #js {"nonce" (generateNonce)}
                (obj/extend (generateSpec cred))))]
       #js {:generateScryptParameters generateScryptParameters
            :proofFromSecret proofFromSecret
            :proofIsVerified proofIsVerified
            :credentialFromProof credentialFromProof
            :challengeFromCredential challengeFromCredential})))
