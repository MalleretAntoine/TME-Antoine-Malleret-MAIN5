import hashlib, time, sys, argparse
#26 00 2eme etage
def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--op", default="Katherine", help='nom opérateur (préfixe ASCII), défaut: "Katherine"')
    ap.add_argument("--bits", type=int, default=56, help="nb de bits à faire matcher (défaut 56)")
    ap.add_argument("--seed", type=int, default=1, help="graine initiale x0 (défaut 1)")
    ap.add_argument("--progress-every", type=int, default=1_000_000, help="log toutes N itérations")
    return ap.parse_args()

def make_f(op_bytes: bytes, out_bytes: int):
    def f(v_int: int) -> int:
        v = v_int.to_bytes(out_bytes, 'big')
        h = hashlib.sha256(op_bytes + v).digest()
        return int.from_bytes(h[:out_bytes], 'big')
    return f

def floyd_collision_preimages(f, x0=1, progress_every=1_000_000, max_iters=None):
    """
Renvoie (a,b) avec a!=b et f(a)==f(b), via Floyd:
      Phase 1: meeting tortoise==hare
      Phase 2: mu (début de cycle)
      Phase 3: lambda (longueur cycle)
      Phase 4: a = x_{mu-1} (ou x0 si mu==0), b = a avancé de lambda pas
    """
    t0 = time.time()
    # Phase 1
    tortoise = f(x0)
    hare = f(f(x0))
    steps = 0
    while tortoise != hare:
        if max_iters is not None and steps >= max_iters:
            return None, None
        tortoise = f(tortoise)
        hare = f(f(hare))
        steps += 1
        if progress_every and steps % progress_every == 0:
            print(f"[phase1] iters={steps:,} elapsed={time.time()-t0:.1f}s")

    # Phase 2: mu
    mu = 0
    tortoise = x0
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        mu += 1

    # Phase 3: lambda
    lam = 1
    hare = f(tortoise)
    while tortoise != hare:
        hare = f(hare)
        lam += 1
#Phase 4: construire deux préimages distinctes des mêmes images
    if mu == 0:
        a = x0
    else:
        a = x0
        for _ in range(mu - 1):
            a = f(a)
    b = a
    for _ in range(lam):
        b = f(b)

    if a == b or f(a) != f(b):
        return None, None
    return a, b

def main():
    args = parse_args()
    op = args.op.encode("ascii")
    OUT_BYTES = (args.bits + 7)//8
    f = make_f(op, OUT_BYTES)

    print(f"Operator: {op!r}   TARGET_BITS={args.bits}   OUT_BYTES={OUT_BYTES}   seed={args.seed}")
    print("Recherche collision (Floyd)…")
    tstart = time.time()
    a, b = floyd_collision_preimages(f, x0=args.seed, progress_every=args.progress_every)
    if a is None:
        print("Échec — réessaie avec un autre seed, ou baisse --bits pour tester.")
        sys.exit(1)
    elapsed = time.time() - tstart

    key_a = (op + a.to_bytes(OUT_BYTES, 'big'))
    key_b = (op + b.to_bytes(OUT_BYTES, 'big'))
    ha = hashlib.sha256(key_a).hexdigest()
    hb = hashlib.sha256(key_b).hexdigest()

    print("\nSuccès !")
    print(f"Temps: {elapsed:.1f}s")
    print("Suffixe A (int):", a)
    print("Suffixe B (int):", b)
    print("Key A (hex):", key_a.hex())
    print("Key B (hex):", key_b.hex())
    print("SHA256 A:", ha)
    print("SHA256 B:", hb)
    pref_hex = 2*OUT_BYTES  # 2 hex chars par octet
    print(f"Prefix commun ({OUT_BYTES} bytes):", ha[:pref_hex], hb[:pref_hex], "=>", ha[:pref_hex]==hb[:pref_hex])

    # Valeurs prêtes à soumettre (en hex)
    print("\n----- À soumettre -----")
    print("FIRST_KEY_HEX =", key_a.hex())
    print("SECOND_KEY_HEX =", key_b.hex())

if __name__ == "__main__":
    main()