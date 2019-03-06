(ns nuid.zka
  (:require
   [nuid.cryptography :as crypto]
   [nuid.ecc :as ecc]
   [nuid.bn :as bn]))

(def protocol-dispatch #(:id (:protocol %)))

(defmulti generate-pub protocol-dispatch)
(defmethod generate-pub :knizk
  [{:keys [curve keyfn secret]}]
  (ecc/mul (ecc/base-point curve) (keyfn secret)))

(defmulti generate-proof protocol-dispatch)
(defmethod generate-proof :knizk
  [{:keys [protocol curve keyfn hashfn pub secret nonce]}]
  (let [q (ecc/prime-order curve)
        r (crypto/randlt 32 q)
        A (ecc/mul (ecc/base-point curve) r)
        c (hashfn (str (ecc/pt->base64 pub)
                       (bn/bn->str nonce 16)
                       (ecc/pt->base64 A)))
        x (keyfn secret)
        s (bn/modulus (bn/add (bn/mul c x) r) q)]
    {:c c :s s}))

(defmulti verified? protocol-dispatch)
(defmethod verified? :knizk
  [{:keys [curve hashfn pub nonce c s]}]
  (let [A (ecc/add (ecc/mul (ecc/base-point curve) s)
                   (ecc/neg (ecc/mul pub c)))
        H (hashfn (str (ecc/pt->base64 pub)
                       (bn/bn->str nonce 16)
                       (ecc/pt->base64 A)))]
    (bn/eq? H c)))

(defn coerce [{:keys [curve keyfn hashfn] :as opts}]
  (merge opts {:hashfn (comp bn/str->bn :result (crypto/generate-hashfn hashfn))
               :keyfn (comp bn/str->bn :result (crypto/generate-hashfn keyfn))
               :curve (ecc/supported-curves (:id curve))}))

#?(:cljs (def exports
           #js {:generate-proof generate-proof
                :generate-pub generate-pub
                :verified? verified?
                :coerce coerce}))
