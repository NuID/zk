(ns nuid.zka
  (:require
   [nuid.cryptography :as crypto]
   [nuid.ecc :as ecc]
   [nuid.bn :as bn]))

(def default-version
  {:protocol :schnorrsnizk
   :curve :ed25519
   :keyfn {:fn :scrypt :n 4096 :r 8}
   :hashfn {:fn :sha512}})

(def relation (bn/str->bn "3"))

(defmulti generate-proof :protocol)
(defmethod generate-proof :schnorrsnizk
  [{:keys [protocol curve keyfn hashfn r1 r2 secret secret-key b]}]
  (let [cur (get ecc/supported-curves curve)
        G (ecc/G cur)
        k (or secret-key ((crypto/generate-hashfn keyfn) secret))
        a (bn/str->bn (:result k))
        A (ecc/mul G a)
        rel (bn/mul a (bn/add b relation))
        C (ecc/mul G rel)
        R1 (ecc/mul G r1)
        R2 (ecc/mul G r2)
        RA (ecc/mul A r2)
        hfn (crypto/generate-hashfn hashfn)
        h (->> [R1 R2 RA]
               (map ecc/pt->hex)
               clojure.string/join
               hfn)
        c (bn/str->bn (:result h))
        n (ecc/n cur)
        s1 (-> (bn/mul c a)
               (bn/add r1)
               (bn/modulus n))
        s2 (-> (bn/mul c b)
               (bn/add r2)
               (bn/modulus n))]
    {:protocol protocol
     :curve curve
     :keyfn (dissoc k :result)
     :hashfn (dissoc h :result)
     :A A
     :C C
     :s1 s1
     :s2 s2
     :c c
     :r1 r1
     :r2 r2
     :b b}))

(defmulti generate-parameters :protocol)
(defmethod generate-parameters :schnorrsnizk
  [{:keys [curve] :as opts}]
  (let [n (ecc/n (get ecc/supported-curves curve))
        r1 (crypto/randlt 32 n)
        r2 (crypto/randlt 32 n)]
    (select-keys
     (generate-proof (assoc opts :r1 r1 :r2 r2))
     [:protocol :curve :keyfn :hashfn :c :r1 :r2])))

(defmulti verify :protocol)
(defmethod verify :schnorrsnizk
  [{:keys [curve c r1 r2 A C s1 s2 b]}]
  (let [G (ecc/G (get ecc/supported-curves curve))
        B (ecc/mul G b)
        R1 (ecc/mul G r1)
        R2 (ecc/mul G r2)
        RA (ecc/mul A r2)]
    (and (ecc/eq (ecc/mul G s1)
                 (ecc/add R1 (ecc/mul A c)))
         (ecc/eq (ecc/mul G s2)
                 (ecc/add R2 (ecc/mul B c)))
         (ecc/eq (ecc/mul A s2)
                 (ecc/add
                  RA
                  (ecc/mul
                   (ecc/add
                    C
                    (ecc/neg
                     (ecc/mul
                      A
                      relation)))
                   c))))))

#?(:cljs (def exports
           #js {:generate-parameters generate-parameters
                :default-version default-version
                :generate-proof generate-proof
                :verify verify}))
