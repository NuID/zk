(ns nuid.zk
  (:require
   [nuid.zk.knizk]
   [nuid.zk.protocol :as protocol]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]])))

(def protocols
  #{::protocol/knizk})

(s/def ::protocol protocols)

(def pub       protocol/pub)
(def proof     protocol/proof)
(def verified? protocol/verified?)

(s/def ::parameters (s/multi-spec protocol/parameters-multi-spec ::protocol))
(s/def ::credential (s/multi-spec protocol/credential-multi-spec ::protocol))
(s/def ::challenge  (s/multi-spec protocol/challenge-multi-spec  ::protocol))
(s/def ::provable   (s/multi-spec protocol/provable-multi-spec   ::protocol))
(s/def ::proof      (s/multi-spec protocol/proof-multi-spec      ::protocol))
(s/def ::verifiable (s/multi-spec protocol/verifiable-multi-spec ::protocol))
(s/def ::verified   (s/multi-spec protocol/verified-multi-spec   ::protocol))
