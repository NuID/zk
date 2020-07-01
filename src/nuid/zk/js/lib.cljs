(ns nuid.zk.js.lib
  (:require
   [clojure.spec.alpha :as s]
   [nuid.lib :as lib]
   [nuid.zk.lib :as zk.lib]))

(defn ->js
  ([data]
   (->>
    (zk.lib/stringify data)
    (clj->js)))
  ([spec data]
   (->>
    (s/unform spec data)
    (->js))))

(defn ->clj
  ([data]
   (->>
    (js->clj data :keywordize-keys true)
    (zk.lib/keywordize)))
  ([spec data]
   (->>
    (->clj data)
    (s/conform spec))))

(def credential-key?
  (into
   (hash-set)
   (map lib/fqn)
   zk.lib/credential-keys))
