
# Taproot default signature schema

inputs:

- c: tapbranch commitment
- a: auxilary
- s: secret

q=Taptweak

b=Sighash_byte

$$ 
even(x)= mod(xG,2) ==0? x : n-x \\

X=sG \\

d'=s+H(X|c) \\

P=d'G \\

d=even(d')\\ 


t=XOR(q,H(a)) \\

r=H(t|P|m) \\

R=rG \\

s=H(R|P|m)q+even(r) \\

signature = (s|R|b)$$

The total bytes is 65 bytes


---

# verification

$$
    P=even(pk) \\
    R=sig[0:32] \\
    s=sig[32:64] \\
    R+H(R|P|m)P == sG

$$


<!-- The algorithm Verify(pk, m, sig) is defined as:
Let P = lift_x(int(pk)); fail if that fails.
Let r = int(sig[0:32]); fail if r ≥ p.
Let s = int(sig[32:64]); fail if s ≥ n.
Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
Let R = s⋅G - e⋅P.
Fail if is_infinite(R).
Fail if not has_even_y(R).
Fail if x(R) ≠ r.
Return success iff no failure occurred before reaching this point. -->



<!-- Let p = c[1:33] and let P = lift_x(int(p)) where lift_x and [:] are defined as in BIP340. Fail if this point is not on the curve.
Let v = c[0] & 0xfe and call it the leaf version[7].
Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash.
For j in [0,1,...,m-1]:
Let ej = c[33+32j:65+32j].
Let kj+1 depend on whether kj < ej (lexicographically)[8]:
If kj < ej: kj+1 = hashTapBranch(kj || ej)[9].
If kj ≥ ej: kj+1 = hashTapBranch(ej || kj).
Let t = hashTapTweak(p || km).
If t ≥ 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 (order of secp256k1), fail.
Let Q = P + int(t)G.
If q ≠ x(Q) or c[0] & 1 ≠ y(Q) mod 2, fail[10]. -->