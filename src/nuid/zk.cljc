(ns nuid.zk
  (:require
   [nuid.elliptic.curve.point :as point]
   [nuid.elliptic.curve :as curve]
   [nuid.cryptography :as crypt]
   [nuid.base64 :as base64]
   [nuid.bn :as bn]))

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
     #js {:isVerified
          (fn [spec pub nonce proof]
            (let [params (coerce (js->clj spec :keywordize-keys true))
                  nonce (bn/from nonce)
                  proof (js->clj proof :keywordize-keys true)]
              (verified? (merge params proof {:pub pub :nonce nonce}))))
          :proof
          (fn [spec pub nonce secret]
            (let [params (coerce (js->clj spec :keywordize-keys true))
                  nonce (bn/from nonce)]
              (clj->js (proof (merge params {:pub pub :nonce nonce :secret secret})))))
          :pub
          (fn [spec secret]
            (let [params (coerce (js->clj spec :keywordize-keys true))]
              (pub (merge params {:secret secret}))))}))
