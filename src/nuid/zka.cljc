(ns nuid.zka
  (:require
   [nuid.cryptography :as crypto]
   [nuid.ecc :as ecc]
   [nuid.bn :as bn]))

(defmulti generate-proof :protocol)
(defmethod generate-proof :knizk
  [{:keys [protocol curve keyfn hashfn pub secret nonce]}]
  (let [q (ecc/prime-order curve)
        r (crypto/randlt 32 q)
        A (ecc/mul (ecc/base-point curve) r)
        c (hashfn (str (ecc/pt->hex pub)
                       (bn/bn->str nonce 16)
                       (ecc/pt->hex A)))
        x (keyfn secret)
        s (bn/modulus (bn/add (bn/mul c x) r) q)]
    {:c c :s s}))

(defmulti verified? :protocol)
(defmethod verified? :knizk
  [{:keys [curve hashfn pub nonce c s]}]
  (let [A (ecc/add (ecc/mul (ecc/base-point curve) s)
                   (ecc/neg (ecc/mul pub c)))
        H (hashfn (str (ecc/pt->hex pub)
                       (bn/bn->str nonce 16)
                       (ecc/pt->hex A)))]
    (bn/eq? H c)))

#?(:cljs (def exports
           #js {:generate-proof generate-proof
                :verified? verified?}))
