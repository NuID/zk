(ns nuid.zk
  (:require
   [nuid.elliptic.curve.point :as point]
   [nuid.elliptic.curve :as curve]
   [nuid.cryptography :as crypt]
   [nuid.base64 :as base64]
   [nuid.bn :as bn]))

(def dispatch (comp :id :protocol))

(defmulti pub dispatch)
(defmethod pub :knizk
  [{:keys [curve keyfn secret]}]
  (point/mul (curve/base curve) (keyfn secret)))

(defmulti proof dispatch)
(defmethod proof :knizk
  [{:keys [protocol curve keyfn hashfn pub secret nonce]}]
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
(defmethod verified? :knizk
  [{:keys [curve hashfn pub nonce c s]}]
  (let [A (point/add (point/mul (curve/base curve) s)
                     (point/neg (point/mul pub c)))
        H (hashfn (str (base64/encode pub)
                       (bn/str nonce 16)
                       (base64/encode A)))]
    (bn/eq? H c)))

(defn coerce
  "Coerces pure data into representations used by `nuid.zk` fns"
  [{:keys [curve keyfn hashfn] :as opts}]
  (merge opts {:hashfn (comp bn/from :digest (crypt/hashfn hashfn))
               :keyfn (comp bn/from :digest (crypt/hashfn keyfn))
               :curve (curve/from (:id curve))}))

#?(:cljs
   (def exports
     #js {:coerce #(coerce (js->clj % :keywordize-keys true))
          :verified? verified?
          :dispatch dispatch
          :proof proof
          :pub pub}))
