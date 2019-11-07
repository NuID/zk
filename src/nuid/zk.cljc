(ns nuid.zk
  (:require
   [nuid.elliptic.curve.point :as point]
   [nuid.elliptic.curve :as curve]
   [nuid.cryptography :as crypt]
   [nuid.base64 :as base64]
   [nuid.bn :as bn]
   #?@(:clj
       [[clojure.spec-alpha2.gen :as gen]
        [clojure.spec-alpha2 :as s]]
       :cljs
       [[clojure.spec.gen.alpha :as gen]
        [clojure.test.check.generators]
        [clojure.spec.alpha :as s]
        [goog.object :as obj]])))

;; TODO: clean up once cljs supports `s/select`
(s/def ::id #{"knizk"})
(s/def ::protocol (s/keys :req-un [::id]))

(s/def ::secret
  (s/with-gen
    (s/and string? not-empty)
    (fn [] (gen/string-ascii))))

(s/def ::conformed-hashfn
  (s/and fn?
         (fn [f] (s/valid? ::crypt/hashfn-parameters
                           (::crypt/opts (meta f))))
         (fn [f] (::conformed? (meta f)))))

(s/def ::hashfn-conformer
  (s/conformer
   (fn [x]
     (if (s/valid? ::conformed-hashfn x)
       x
       (let [c (s/conform ::crypt/hashfn x)]
         (if (s/invalid? c)
           ::s/invalid
           (with-meta
             (comp bn/from :digest c)
             (assoc (meta c) ::conformed? true))))))
   (fn [x]
     (if (s/valid? ::crypt/hashfn-parameters x)
       x
       (if (s/valid? ::crypt/conformed-hashfn x)
         (::crypt/opts (meta x))
         ::s/invalid)))))

(s/def ::keyfn
  (s/with-gen
    ::hashfn-conformer
    (fn [] (->> (s/gen ::crypt/keyfn-parameters)
                (gen/fmap (partial s/conform ::hashfn-conformer))))))

(s/def ::hashfn
  (s/with-gen
    ::hashfn-conformer
    (fn [] (->> (s/gen ::crypt/hashfn-parameters)
                (gen/such-that (comp #{"sha256" "sha512"} :id))
                (gen/fmap (fn [m] (dissoc m :salt)))
                (gen/fmap (partial s/conform ::hashfn-conformer))))))

(s/def ::pub ::point/point)
(s/def ::pri ::bn/bn)

(s/def ::knizk-parameters
  (s/keys :req-un [::protocol
                   ::curve/curve
                   ::keyfn
                   ::hashfn]))

(s/def ::parameters
  (s/or ::knizk ::knizk-parameters))

(s/def ::credential
  (s/keys :req-un [::keyfn ::pub]))

;; TODO: not using `s/merge` because it
;; only conforms against it's first argument
(s/def ::challenge
  (s/keys :req-un [::protocol
                   ::curve/curve
                   ::keyfn
                   ::hashfn
                   ::pub
                   ::crypt/nonce]))

(defn- dispatch
  [x]
  (let [x (s/conform ::parameters x)]
    (if (s/invalid? x)
      x
      (first x))))

(defmulti  pub dispatch)
(defmethod pub ::knizk
  [{:keys [curve keyfn secret pri]}]
  (point/mul
   (curve/base curve)
   (or pri (keyfn secret))))

(defmulti  proof dispatch)
(defmethod proof ::knizk
  [{:keys [curve keyfn hashfn pub nonce secret pri]}]
  (let [q (curve/order curve)
        r (crypt/generate-secure-random-bn-lt 32 q)
        A (point/mul (curve/base curve) r)
        c (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))
        x (or pri (keyfn secret))
        s (bn/mod (bn/add (bn/mul c x) r) q)]
    {:c c :s s}))

(defmulti  verified? dispatch)
(defmethod verified? ::knizk
  [{:keys [curve hashfn pub nonce c s]}]
  (let [A (point/add (point/mul (curve/base curve) s)
                     (point/neg (point/mul pub c)))
        H (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))]
    (bn/eq? H c)))

(s/def ::c ::bn/bn)
(s/def ::s ::bn/bn)

(s/def ::knizk-proof-data
  (s/keys :req-un [::c ::s]))

(s/def ::proof-data
  (s/or ::knizk ::knizk-proof-data))

(s/def ::knizk-proof
  (s/with-gen
    (s/and ::challenge
           ::knizk-proof-data
           verified?)
    (fn [] (->> (s/gen ::knizk-parameters)
                (gen/fmap (fn [m] (assoc m :nonce (gen/generate (s/gen ::crypt/nonce)))))
                (gen/fmap (fn [m] (assoc m :secret (gen/generate (s/gen ::secret)))))
                (gen/fmap (fn [m] (assoc m :pub (pub m))))
                (gen/fmap (fn [m] (merge m (proof m))))))))

(s/def ::proof
  (s/or ::knizk ::knizk-proof))

#?(:cljs
   (def exports
     (letfn [(generateScryptParameters
               [& [params]]
               (doto (clj->js (crypt/generate-default-scrypt-parameters))
                 (obj/extend (or params #js {}))))

             (generateSpec
              [& [spec]]
              (doto #js {"protocol" #js {"id" "knizk"}
                         "curve"    #js {"id" "secp256k1"}
                         "keyfn"    (generateScryptParameters)
                         "hashfn"   #js {"id"                 "sha256"
                                         "normalization-form" "NFKC"}}
                (obj/extend (or spec #js {}))))

             (coerceSpec
              [spec]
              (as-> (generateSpec spec) $
                (js->clj $ :keywordize-keys true)
                (s/conform ::knizk-parameters $)))

             (generatePub
              ([secret] (generatePub nil secret))
              ([spec secret]
               (->> (merge
                     (coerceSpec spec)
                     {:secret secret})
                    (pub)
                    (s/unform ::pub)
                    (clj->js))))

             (coercePub
              [pub]
              (->> (js->clj pub :keywordize-keys true)
                   (s/conform ::pub)))

             (generateNonce
              []
              (->> (s/gen ::crypt/nonce)
                   (gen/generate)
                   (s/unform ::crypt/nonce)))

             (coerceBn
              [x]
              (s/conform ::bn/bn x))

             (generateProof
              [spec pub nonce secret]
              (->> (merge
                    (coerceSpec spec)
                    {:pub    (coercePub pub)
                     :nonce  (coerceBn nonce)
                     :secret secret})
                   (proof)
                   (s/unform
                    (s/keys
                     :req-un [::c ::s]))
                   (clj->js)))

             (proofFromSecret
              ([secret] (proofFromSecret nil secret))
              ([spec secret]
               (let [spec  (generateSpec spec)
                     pub   (or (obj/get spec "pub") (generatePub spec secret))
                     nonce (or (obj/get spec "nonce") (generateNonce))
                     proof (generateProof spec pub nonce secret)]
                 (doto #js {"nonce" nonce "pub" pub}
                   (obj/extend spec proof)))))

             (coerceProof
              [proof]
              (merge
               (coerceSpec proof)
               {:pub   (coercePub (obj/get proof "pub"))
                :nonce (coerceBn (obj/get proof "nonce"))
                :c     (coerceBn (obj/get proof "c"))
                :s     (coerceBn (obj/get proof "s"))}))

             (proofIsVerified
              [proof]
              (verified? (coerceProof proof)))

             (isCredentialKey
              [k]
              (#{"keyfn" "pub"} k))

             (credentialFromProof
              [proof]
              (obj/filter proof (fn [_ k _] (isCredentialKey k))))

             (challengeFromCredential
              [cred]
              (doto #js {"nonce" (generateNonce)}
                (obj/extend (generateSpec cred))))]
       #js {:generateScryptParameters generateScryptParameters
            :proofFromSecret          proofFromSecret
            :proofIsVerified          proofIsVerified
            :credentialFromProof      credentialFromProof
            :challengeFromCredential  challengeFromCredential})))
