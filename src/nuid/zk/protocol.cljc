(ns nuid.zk.protocol)

(def protocols
  #{::knizk})

(defmulti pub        :nuid.zk/protocol)
(defmulti proof      :nuid.zk/protocol)
(defmulti verified?  :nuid.zk/protocol)
(defmulti credential :nuid.zk/protocol)

(defmulti parameters-multi-spec :nuid.zk/protocol)
(defmulti credential-multi-spec :nuid.zk/protocol)
(defmulti challenge-multi-spec  :nuid.zk/protocol)
(defmulti provable-multi-spec   :nuid.zk/protocol)
(defmulti proof-multi-spec      :nuid.zk/protocol)
(defmulti verifiable-multi-spec :nuid.zk/protocol)
(defmulti verified-multi-spec   :nuid.zk/protocol)
