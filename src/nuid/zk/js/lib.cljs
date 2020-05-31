(ns nuid.zk.js.lib
  (:require
   [clojure.spec.alpha :as s]
   [nuid.lib :as lib]
   [nuid.zk.lib :as zk.lib]))

(defn ->js
  [spec data]
  (->>
   (s/unform spec data)
   (zk.lib/stringify)
   (clj->js)))

(defn ->clj
  [spec data]
  (->>
   (js->clj data :keywordize-keys true)
   (zk.lib/keywordize)
   (s/conform spec)))

(def credential-keys
  (into
   (hash-set)
   (map lib/fqn)
   zk.lib/credential-keys))

(defn obj-credential-filter
  [_ k _]
  (credential-keys k))
