(ns nuid.zk.knizk
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.base64 :as base64]
   [nuid.bn :as bn]
   [nuid.cryptography.bn :as crypt.bn]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.cryptography.hash.bn :as hash.bn]
   [nuid.elliptic.curve.point :as point]
   [nuid.elliptic.curve :as curve]
   [nuid.spec.lib :as spec.lib]
   [nuid.zk.protocol :as protocol]))

(s/def ::secret
  (s/with-gen
    (s/and string? seq)
    (fn [] (gen/string-ascii))))

(s/def ::curve  ::curve/curve)
(s/def ::hashfn ::hash.bn/hashfn)
(s/def ::keyfn  ::hash.bn/keyfn)
(s/def ::pub    ::point/point)
(s/def ::pri    ::bn/bn)
(s/def ::nonce  ::crypt.bn/nonce)

(s/def ::parameters
  (s/keys
   :req
   [::curve
    ::hashfn
    ::keyfn]))

(s/def ::credential
  (s/keys
   :req
   [::keyfn
    ::pub]))

(s/def ::challenge
  (s/keys
   :req
   [::curve
    ::hashfn
    ::keyfn
    ::nonce]
   :opt
   [::pub]))

(s/def ::provable
  (s/and
   (s/keys
    :req
    [::curve
     ::hashfn
     ::keyfn
     ::pub
     ::nonce
     (or
      ::secret
      ::pri)])))

(s/def ::c ::bn/bn)
(s/def ::s ::bn/bn)

(s/def ::proof
  (s/keys
   :req [::c ::s]))

(s/def ::verifiable
  (s/keys
   :req
   [::curve
    ::hashfn
    ::pub
    ::nonce
    ::c
    ::s]))

(defmethod protocol/pub ::protocol/knizk
  [{::keys [curve keyfn pri secret]}]
  {::pub (point/mul
          (curve/base curve)
          (or pri (keyfn secret)))})

(defmethod protocol/proof ::protocol/knizk
  [{::keys [curve hashfn keyfn pub pri secret nonce]}]
  (let [q (curve/order curve)
        r (crypt.bn/generate-secure-random-lt 32 q)
        A (point/mul (curve/base curve) r)
        c (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))
        x (or pri (keyfn secret))
        s (bn/mod (bn/add (bn/mul c x) r) q)]
    {::c c ::s s}))

(defmethod protocol/verified? ::protocol/knizk
  [{::keys [curve hashfn pub nonce c s]}]
  (let [A (point/add (point/mul (curve/base curve) s)
                     (point/neg (point/mul pub c)))
        H (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))]
    (bn/eq? H c)))

(s/def ::verified
  (s/with-gen
    (s/and
     ::verifiable
     protocol/verified?)
    (fn []
      (->>
       (s/gen ::parameters)
       (gen/fmap (fn [m] (assoc m ::nonce  (gen/generate (s/gen ::crypt.bn/nonce)))))
       (gen/fmap (fn [m] (assoc m ::secret (gen/generate (s/gen ::secret)))))
       (gen/fmap (fn [m] (assoc m :nuid.zk/protocol ::protocol/knizk)))
       (gen/fmap (fn [m] (merge m (protocol/pub m))))
       (gen/fmap (fn [m] (merge m (protocol/proof m))))))))

(defn credential
  [x]
  (spec.lib/select-keys ::credential x))

(defmethod protocol/credential ::protocol/knizk
  [x]
  (->>
   (spec.lib/keys-spec->keys ::credential)
   (into #{:nuid.zk/protocol})
   (select-keys x)))

(defmethod protocol/parameters-multi-spec ::protocol/knizk [_] ::parameters)
(defmethod protocol/credential-multi-spec ::protocol/knizk [_] ::credential)
(defmethod protocol/challenge-multi-spec  ::protocol/knizk [_] ::challenge)
(defmethod protocol/provable-multi-spec   ::protocol/knizk [_] ::provable)
(defmethod protocol/proof-multi-spec      ::protocol/knizk [_] ::proof)
(defmethod protocol/verifiable-multi-spec ::protocol/knizk [_] ::verifiable)
(defmethod protocol/verified-multi-spec   ::protocol/knizk [_] ::verified)

(defn default-challenge-parameters
  []
  {::curve  {::curve/id ::curve/secp256k1}
   ::hashfn (hash/default-parameters {::hash/algorithm ::hash.alg/sha256})
   ::keyfn  (hash/default-parameters {::hash/algorithm ::hash.alg/scrypt})
   ::nonce  (s/unform ::crypt.bn/nonce (gen/generate (s/gen ::crypt.bn/nonce)))})
