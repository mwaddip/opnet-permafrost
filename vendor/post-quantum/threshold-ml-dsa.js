
/**
 * Threshold ML-DSA: t-of-n threshold signing producing standard FIPS 204 signatures.
 *
 * Based on "Threshold Signatures Reloaded" (Borin, Celi, del Pino, Espitau, Niot, Prest, 2025).
 * Reference Go implementation: GuilhemN/threshold-ml-dsa-and-raccoon (Cloudflare CIRCL).
 *
 * Produces signatures verifiable by standard ml_dsa44/65/87.verify() without
 * knowing they were threshold-produced.
 *
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { shake256 } from '@noble/hashes/sha3.js';
import { XOF128, XOF256 } from "./_crystals.js";
import { MLDSAPrimitives, N, Q } from "./ml-dsa-primitives.js";
import { PARAMS } from "./ml-dsa.js";
import { abytes, cleanBytes, equalBytes, getMessage, randomBytes } from "./utils.js";
/** Private state from round 1. Contains sensitive key material — DO NOT share. */
export class Round1State {
    #stws;
    #commitment;
    #destroyed;
    /** @internal */
    constructor(stws, commitment) {
        this.#stws = stws;
        this.#commitment = commitment;
        this.#destroyed = false;
    }
    /** @internal */
    get _stws() {
        if (this.#destroyed)
            throw new Error('Round1State has been destroyed');
        return this.#stws;
    }
    /** @internal */
    get _commitment() {
        if (this.#destroyed)
            throw new Error('Round1State has been destroyed');
        return this.#commitment;
    }
    /** Zero out all sensitive data in this state. */
    destroy() {
        if (!this.#destroyed) {
            for (const stw of this.#stws)
                stw.fill(0);
            this.#destroyed = true;
        }
    }
}
/** Private state from round 2. Contains message digest. */
export class Round2State {
    #hashes;
    #mu;
    #act;
    #activePartyIds;
    #destroyed;
    /** @internal */
    constructor(hashes, mu, act, activePartyIds) {
        this.#hashes = hashes;
        this.#mu = mu;
        this.#act = act;
        this.#activePartyIds = activePartyIds;
        this.#destroyed = false;
    }
    /** @internal */
    get _hashes() {
        if (this.#destroyed)
            throw new Error('Round2State has been destroyed');
        return this.#hashes;
    }
    /** @internal */
    get _mu() {
        if (this.#destroyed)
            throw new Error('Round2State has been destroyed');
        return this.#mu;
    }
    /** @internal */
    get _act() {
        if (this.#destroyed)
            throw new Error('Round2State has been destroyed');
        return this.#act;
    }
    /** @internal */
    get _activePartyIds() {
        if (this.#destroyed)
            throw new Error('Round2State has been destroyed');
        return this.#activePartyIds;
    }
    /** Zero out message digest. */
    destroy() {
        if (!this.#destroyed) {
            this.#mu.fill(0);
            this.#destroyed = true;
        }
    }
}
/**
 * Threshold ML-DSA signing protocol.
 *
 * Implements FIPS 204 compliant t-of-n threshold signing
 * producing standard ML-DSA signatures. Based on the
 * "Threshold Signatures Reloaded" construction.
 */
export class ThresholdMLDSA {
    static #DKG_RHO_COMMIT = /* @__PURE__ */ new TextEncoder().encode('DKG-RHO-COMMIT');
    static #DKG_BSEED_COMMIT = /* @__PURE__ */ new TextEncoder().encode('DKG-BSEED-COMMIT');
    static #DKG_RHO_AGG = /* @__PURE__ */ new TextEncoder().encode('DKG-RHO-AGG');
    static #DKG_GEN_ASSIGN = /* @__PURE__ */ new TextEncoder().encode('DKG-GEN-ASSIGN');
    static #DKG_BSEED = /* @__PURE__ */ new TextEncoder().encode('DKG-BSEED');
    /** ML-DSA-44 threshold parameters: [K_iter, r, rPrime] indexed by [T-2][N-2]. */
    // prettier-ignore
    static #PARAMS_44 = {
        '2': [[2, 252778, 252833]],
        '3': [[3, 310060, 310138], [4, 246490, 246546]],
        '4': [[3, 305919, 305997], [7, 279235, 279314], [8, 243463, 243519]],
        '5': [[3, 285363, 285459], [14, 282800, 282912], [30, 259427, 259526], [16, 239924, 239981]],
        '6': [[4, 300265, 300362], [19, 277014, 277139], [74, 268705, 268831], [100, 250590, 250686], [37, 219245, 219301]],
    };
    /** ML-DSA-65 threshold parameters. Derived from same formulas, scaled for K=6,L=5. */
    // prettier-ignore
    static #PARAMS_65 = {
        '2': [[2, 344000, 344080]],
        '3': [[3, 421700, 421810], [4, 335200, 335290]],
        '4': [[3, 416000, 416110], [7, 379600, 379710], [8, 331000, 331090]],
        '5': [[3, 388000, 388130], [14, 384600, 384750], [30, 352800, 352940], [16, 326200, 326280]],
        '6': [[4, 408300, 408430], [19, 376700, 376870], [74, 365400, 365570], [100, 340700, 340830], [37, 298000, 298080]],
    };
    /** ML-DSA-87 threshold parameters. Derived from same formulas, scaled for K=8,L=7. */
    // prettier-ignore
    static #PARAMS_87 = {
        '2': [[2, 442000, 442100]],
        '3': [[3, 541600, 541740], [4, 430600, 430710]],
        '4': [[3, 534200, 534340], [7, 487500, 487640], [8, 425100, 425210]],
        '5': [[3, 498200, 498370], [14, 494200, 494400], [30, 453300, 453470], [16, 419100, 419210]],
        '6': [[4, 524300, 524470], [19, 483600, 483820], [74, 469200, 469420], [100, 437400, 437570], [37, 382800, 382910]],
    };
    static #ALL_PARAMS = {
        44: ThresholdMLDSA.#PARAMS_44,
        65: ThresholdMLDSA.#PARAMS_65,
        87: ThresholdMLDSA.#PARAMS_87,
    };
    /** Size in bytes of one 23-bit-packed polynomial. */
    static #POLY_Q_SIZE = (N * 23) / 8; // 736
    static MAX_PARTIES = 6;
    #primitives;
    params;
    constructor(primitives, params) {
        this.#primitives = primitives;
        this.params = params;
    }
    /**
     * Create a ThresholdMLDSA instance for the given security level and threshold parameters.
     * @param securityLevel - 44, 65, or 87 (or 128, 192, 256)
     * @param T - Minimum number of parties needed to sign
     * @param N_ - Total number of parties
     */
    static create(securityLevel, T, N_) {
        const params = ThresholdMLDSA.getParams(T, N_, securityLevel);
        const opts = ThresholdMLDSA.#getDSAOpts(securityLevel);
        const primitives = new MLDSAPrimitives(opts);
        return new ThresholdMLDSA(primitives, params);
    }
    /** Get threshold parameters for given (T, N, securityLevel). */
    static getParams(T, N_, securityLevel) {
        const level = ThresholdMLDSA.#normalizeSecurityLevel(securityLevel);
        const table = ThresholdMLDSA.#ALL_PARAMS[level];
        if (!table)
            throw new Error(`Unsupported security level: ${securityLevel}`);
        if (T < 2)
            throw new Error('Threshold T must be >= 2');
        if (T > N_)
            throw new Error('Threshold T must be <= N');
        if (N_ > ThresholdMLDSA.MAX_PARTIES)
            throw new Error(`N must be <= ${ThresholdMLDSA.MAX_PARTIES}`);
        if (N_ < 2)
            throw new Error('N must be >= 2');
        const entries = table[String(N_)];
        if (!entries)
            throw new Error(`No parameters for N=${N_}`);
        const idx = T - 2;
        if (idx < 0 || idx >= entries.length)
            throw new Error(`No parameters for T=${T}, N=${N_}`);
        const [K_iter, r, rPrime] = entries[idx];
        return { T, N: N_, K_iter, nu: 3.0, r, rPrime };
    }
    static #getDSAOpts(securityLevel) {
        let paramKey;
        let cTildeBytes;
        if (securityLevel === 44 || securityLevel === 128) {
            paramKey = '2';
            cTildeBytes = 32;
        }
        else if (securityLevel === 65 || securityLevel === 192) {
            paramKey = '3';
            cTildeBytes = 48;
        }
        else if (securityLevel === 87 || securityLevel === 256) {
            paramKey = '5';
            cTildeBytes = 64;
        }
        else {
            throw new Error(`Unsupported security level: ${securityLevel}`);
        }
        const p = PARAMS[paramKey];
        return {
            ...p,
            CRH_BYTES: 64,
            TR_BYTES: 64,
            C_TILDE_BYTES: cTildeBytes,
            XOF128,
            XOF256,
        };
    }
    static #normalizeSecurityLevel(level) {
        if (level === 128)
            return 44;
        if (level === 192)
            return 65;
        if (level === 256)
            return 87;
        return level;
    }
    static #encodeU8(v) {
        return new Uint8Array([v & 0xff]);
    }
    static #encodeU16LE(v) {
        return new Uint8Array([v & 0xff, (v >> 8) & 0xff]);
    }
    /** Fill polynomial with uniform random values in [0, Q). */
    static #fillUniformModQ(poly) {
        let filled = 0;
        while (filled < N) {
            // Q/2^23 ≈ 0.999, so rejection rate < 0.1%
            const needed = N - filled;
            const bytes = randomBytes(needed * 3);
            for (let i = 0; i + 2 < bytes.length && filled < N; i += 3) {
                const val = (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16)) & 0x7fffff;
                if (val < Q)
                    poly[filled++] = val;
            }
        }
    }
    /**
     * Additively split a vector of K polynomials into N shares
     * such that sum of all shares equals the input (mod Q).
     * N-1 shares are uniform random; the residual goes to `residualIdx`.
     */
    static #splitVectorK(wb, nParties, residualIdx) {
        const K = wb.length;
        const result = new Array(nParties);
        // Sample N-1 uniform random masks
        for (let j = 0; j < nParties; j++) {
            if (j === residualIdx)
                continue;
            const mask = [];
            for (let k = 0; k < K; k++) {
                const poly = new Int32Array(N);
                ThresholdMLDSA.#fillUniformModQ(poly);
                mask.push(poly);
            }
            result[j] = mask;
        }
        // Compute residual: wb - sum of all other masks (mod Q)
        const residual = [];
        for (let k = 0; k < K; k++) {
            const poly = new Int32Array(N);
            for (let c = 0; c < N; c++) {
                let val = wb[k][c];
                for (let j = 0; j < nParties; j++) {
                    if (j === residualIdx)
                        continue;
                    val -= result[j][k][c];
                }
                poly[c] = ((val % Q) + Q) % Q;
            }
            residual.push(poly);
        }
        result[residualIdx] = residual;
        return result;
    }
    static #getSharingPattern(T, N_) {
        if (T === 2 && N_ === 3)
            return [[3, 5], [6]];
        if (T === 2 && N_ === 4)
            return [
                [11, 13],
                [7, 14],
            ];
        if (T === 3 && N_ === 4)
            return [
                [3, 9],
                [6, 10],
                [12, 5],
            ];
        if (T === 2 && N_ === 5)
            return [
                [27, 29, 23],
                [30, 15],
            ];
        if (T === 3 && N_ === 5)
            return [
                [25, 11, 19, 13],
                [7, 14, 22, 26],
                [28, 21],
            ];
        if (T === 4 && N_ === 5)
            return [[3, 9, 17], [6, 10, 18], [12, 5, 20], [24]];
        if (T === 2 && N_ === 6)
            return [
                [61, 47, 55],
                [62, 31, 59],
            ];
        // prettier-ignore
        if (T === 3 && N_ === 6)
            return [[27, 23, 43, 57, 39], [51, 58, 46, 30, 54], [45, 53, 29, 15, 60]];
        // prettier-ignore
        if (T === 4 && N_ === 6)
            return [[19, 13, 35, 7, 49], [42, 26, 38, 50, 22], [52, 21, 44, 28, 37], [25, 11, 14, 56, 41]];
        // prettier-ignore
        if (T === 5 && N_ === 6)
            return [[3, 5, 33], [6, 10, 34], [12, 20, 36], [9, 24, 40], [48, 17, 18]];
        return null;
    }
    /** 23-bit per coefficient polynomial packing (for full Zq elements). */
    static #polyPackW(p, buf, offset) {
        let v = 0;
        let j = 0;
        let k = 0;
        for (let i = 0; i < N; i++) {
            v = v | ((p[i] & 0x7fffff) << j);
            j += 23;
            while (j >= 8) {
                buf[offset + k] = v & 0xff;
                v >>>= 8;
                j -= 8;
                k++;
            }
        }
    }
    static #polyUnpackW(p, buf, offset) {
        let v = 0;
        let j = 0;
        let k = 0;
        for (let i = 0; i < N; i++) {
            while (j < 23) {
                v = v + ((buf[offset + k] & 0xff) << j);
                j += 8;
                k++;
            }
            const coeff = v & ((1 << 23) - 1);
            // M7 fix: validate unpacked coefficients are in [0, Q)
            if (coeff >= Q)
                throw new Error(`Invalid polynomial coefficient: ${coeff} >= Q`);
            p[i] = coeff;
            v >>>= 23;
            j -= 23;
        }
    }
    /** Pack K_iter arrays of dim polynomials into bytes (23-bit per coefficient). */
    static #packPolys(polys, dim, K_iter) {
        const buf = new Uint8Array(K_iter * dim * ThresholdMLDSA.#POLY_Q_SIZE);
        for (let iter = 0; iter < K_iter; iter++) {
            for (let j = 0; j < dim; j++) {
                ThresholdMLDSA.#polyPackW(polys[iter][j], buf, (iter * dim + j) * ThresholdMLDSA.#POLY_Q_SIZE);
            }
        }
        return buf;
    }
    /** Unpack bytes into K_iter arrays of dim polynomials. */
    static #unpackPolys(buf, dim, K_iter) {
        const expected = K_iter * dim * ThresholdMLDSA.#POLY_Q_SIZE;
        if (buf.length !== expected) {
            throw new Error(`Invalid buffer length: expected ${expected}, got ${buf.length}`);
        }
        const result = [];
        for (let iter = 0; iter < K_iter; iter++) {
            const polys = [];
            for (let j = 0; j < dim; j++) {
                const p = new Int32Array(N);
                ThresholdMLDSA.#polyUnpackW(p, buf, (iter * dim + j) * ThresholdMLDSA.#POLY_Q_SIZE);
                polys.push(p);
            }
            result.push(polys);
        }
        return result;
    }
    /** Sample from hyperball using Box-Muller transform over SHAKE256. */
    static #sampleHyperball(rPrime, nu, K, L, rhop, nonce) {
        const dim = N * (K + L);
        const numSamples = dim + 2; // need even number >= dim for Box-Muller pairs
        const samples = new Float64Array(numSamples);
        // Use SHAKE256 as deterministic RNG
        const h = shake256.create({});
        h.update(new Uint8Array([0x48])); // domain separator 'H'
        h.update(rhop);
        const iv = new Uint8Array(2);
        iv[0] = nonce & 0xff;
        iv[1] = (nonce >> 8) & 0xff;
        h.update(iv);
        const byteBuf = new Uint8Array(numSamples * 8);
        h.xofInto(byteBuf);
        // Box-Muller transform + L2 norm accumulation
        let sq = 0;
        const dv = new DataView(byteBuf.buffer, byteBuf.byteOffset, byteBuf.byteLength);
        for (let i = 0; i < numSamples; i += 2) {
            // Convert 64-bit random to uniform float in [0, 1) using top 53 bits.
            // BigInt >> 11 extracts exactly 53 bits (fits in Number.MAX_SAFE_INTEGER),
            // then multiply by 2^-53 to scale to [0, 1). This avoids double-rounding
            // from Number(uint64) / 2^64 where the numerator exceeds 53-bit precision.
            const u1 = dv.getBigUint64(i * 8, true);
            const u2 = dv.getBigUint64((i + 1) * 8, true);
            const TWO_NEG_53 = 1.1102230246251565e-16; // 2 ** -53, exact in float64
            const f1Raw = Number(u1 >> 11n) * TWO_NEG_53; // [0, 1 - 2^-53]
            const f2 = Number(u2 >> 11n) * TWO_NEG_53;
            // C1 fix: clamp f1 > 0 to avoid log(0) = -Inf → NaN. Probability: 2^-53.
            const f1 = f1Raw === 0 ? Number.MIN_VALUE : f1Raw;
            // Box-Muller
            const r = Math.sqrt(-2 * Math.log(f1));
            const theta = 2 * Math.PI * f2;
            const z1 = r * Math.cos(theta);
            const z2 = r * Math.sin(theta);
            // Accumulate L2 norm BEFORE nu scaling (matches Go reference exactly:
            // Go accumulates sq from unscaled values, including the extra pair beyond dim)
            samples[i] = z1;
            sq += z1 * z1;
            samples[i + 1] = z2;
            sq += z2 * z2;
            // Scale L-dimension components by nu AFTER sq accumulation
            if (i < N * L) {
                samples[i] *= nu;
                if (i + 1 < N * L)
                    samples[i + 1] *= nu;
            }
        }
        // Normalize to sphere of radius rPrime
        const result = new Float64Array(dim);
        const factor = rPrime / Math.sqrt(sq);
        for (let i = 0; i < dim; i++) {
            result[i] = samples[i] * factor;
        }
        return result;
    }
    /** Add two FVecs. */
    static #fvecAdd(a, b) {
        const r = new Float64Array(a.length);
        for (let i = 0; i < a.length; i++)
            r[i] = a[i] + b[i];
        return r;
    }
    /** Check if weighted L2 norm exceeds bound r. */
    static #fvecExcess(v, r, nu, K, L) {
        let sq = 0;
        for (let i = 0; i < L + K; i++) {
            for (let j = 0; j < N; j++) {
                const val = v[i * N + j];
                if (i < L) {
                    sq += (val * val) / (nu * nu);
                }
                else {
                    sq += val * val;
                }
            }
        }
        return sq > r * r;
    }
    /** Convert integer vectors (s1,s2) to FVec with centered mod Q. */
    static #fvecFrom(s1, s2, K, L) {
        const result = new Float64Array(N * (K + L));
        for (let i = 0; i < L + K; i++) {
            for (let j = 0; j < N; j++) {
                let u;
                if (i < L) {
                    u = s1[i][j] | 0;
                }
                else {
                    u = s2[i - L][j] | 0;
                }
                // Center mod Q: smod equivalent
                u = ((u + (Q - 1) / 2) | 0) % Q;
                if (u < 0)
                    u += Q;
                u = u - (Q - 1) / 2;
                result[i * N + j] = u;
            }
        }
        return result;
    }
    /** Round FVec back to integer vectors. */
    static #fvecRound(v, K, L) {
        const z = [];
        const e = [];
        for (let i = 0; i < L; i++)
            z.push(new Int32Array(N));
        for (let i = 0; i < K; i++)
            e.push(new Int32Array(N));
        for (let i = 0; i < L + K; i++) {
            for (let j = 0; j < N; j++) {
                let u = Math.round(v[i * N + j]) | 0;
                // Add Q if negative
                if (u < 0)
                    u += Q;
                if (i < L) {
                    z[i][j] = u;
                }
                else {
                    e[i - L][j] = u;
                }
            }
        }
        return { z, e };
    }
    /**
     * Generate threshold keys from a seed (trusted dealer model).
     *
     * A single trusted dealer generates all N key shares and the public key.
     * After distributing shares to parties over secure channels, the dealer
     * MUST securely erase the seed and all share data.
     *
     * @param seed - 32-byte seed. Default: random.
     */
    keygen(seed) {
        const p = this.#primitives;
        const { K, L, TR_BYTES } = p;
        const params = this.params;
        if (seed === undefined)
            seed = randomBytes(32);
        abytes(seed, 32, 'seed');
        const h = shake256.create({});
        h.update(seed);
        // NIST mode: append K, L
        h.update(new Uint8Array([K, L]));
        // Derive rho (32 bytes)
        const rho = new Uint8Array(32);
        h.xofInto(rho);
        // Expand A matrix
        const xof = p.XOF128(rho);
        const A = [];
        for (let i = 0; i < K; i++) {
            const row = [];
            for (let j = 0; j < L; j++)
                row.push(p.RejNTTPoly(xof.get(j, i)));
            A.push(row);
        }
        xof.clean();
        // Initialize per-party keys
        const sks = [];
        for (let i = 0; i < params.N; i++) {
            const key = new Uint8Array(32);
            h.xofInto(key);
            sks.push({
                id: i,
                rho: rho.slice(),
                key,
                shares: new Map(),
            });
        }
        // Accumulate total secret
        const totalS1 = [];
        const totalS2 = [];
        const totalS1Hat = [];
        const totalS2Hat = [];
        for (let i = 0; i < L; i++) {
            totalS1.push(new Int32Array(N));
            totalS1Hat.push(new Int32Array(N));
        }
        for (let i = 0; i < K; i++) {
            totalS2.push(new Int32Array(N));
            totalS2Hat.push(new Int32Array(N));
        }
        // Gosper's hack: iterate all bitmasks with exactly (N-T+1) bits set among N bits
        let honestSigners = (1 << (params.N - params.T + 1)) - 1;
        while (honestSigners < 1 << params.N) {
            // Sample share seed
            const sSeed = new Uint8Array(64);
            h.xofInto(sSeed);
            // Sample s1, s2 for this share using PolyDeriveUniformLeqEta equivalent
            const shareS1 = [];
            const shareS2 = [];
            for (let j = 0; j < L; j++) {
                shareS1.push(this.#deriveUniformLeqEta(sSeed, j));
            }
            for (let j = 0; j < K; j++) {
                shareS2.push(this.#deriveUniformLeqEta(sSeed, j + L));
            }
            // Compute NTT representations
            const shareS1Hat = shareS1.map((s) => p.NTT.encode(s.slice()));
            const shareS2Hat = shareS2.map((s) => p.NTT.encode(s.slice()));
            const share = {
                s1: shareS1,
                s2: shareS2,
                s1Hat: shareS1Hat,
                s2Hat: shareS2Hat,
            };
            // Distribute share to parties whose bit is set
            for (let i = 0; i < params.N; i++) {
                if ((honestSigners & (1 << i)) !== 0) {
                    sks[i].shares.set(honestSigners, share);
                }
            }
            // Accumulate total
            for (let j = 0; j < L; j++) {
                p.polyAdd(totalS1[j], shareS1[j]);
                p.polyAdd(totalS1Hat[j], shareS1Hat[j]);
            }
            for (let j = 0; j < K; j++) {
                p.polyAdd(totalS2[j], shareS2[j]);
                p.polyAdd(totalS2Hat[j], shareS2Hat[j]);
            }
            // Gosper's hack: next combination
            const c = honestSigners & -honestSigners;
            const r = honestSigners + c;
            honestSigners = (((r ^ honestSigners) >> 2) / c) | r;
        }
        // Normalize total secrets
        for (let j = 0; j < L; j++) {
            for (let i = 0; i < N; i++)
                totalS1[j][i] = p.mod(totalS1[j][i]);
            for (let i = 0; i < N; i++)
                totalS1Hat[j][i] = p.mod(totalS1Hat[j][i]);
        }
        for (let j = 0; j < K; j++) {
            for (let i = 0; i < N; i++)
                totalS2[j][i] = p.mod(totalS2[j][i]);
            for (let i = 0; i < N; i++)
                totalS2Hat[j][i] = p.mod(totalS2Hat[j][i]);
        }
        // Compute t = A*s1 + s2, then Power2Round to get (t0, t1)
        const t1 = [];
        for (let i = 0; i < K; i++) {
            const t = p.newPoly(N);
            for (let j = 0; j < L; j++) {
                p.polyAdd(t, p.MultiplyNTTs(A[i][j], totalS1Hat[j]));
            }
            p.NTT.decode(t);
            p.polyAdd(t, totalS2[i]);
            // Normalize t
            for (let c = 0; c < N; c++)
                t[c] = p.mod(t[c]);
            const { r1 } = p.polyPowerRound(t);
            t1.push(r1);
        }
        // Encode public key
        const publicKey = p.publicCoder.encode([rho, t1]);
        // Compute tr = H(pk)
        const tr = shake256(publicKey, { dkLen: TR_BYTES });
        // Finalize shares
        const shares = sks.map((sk) => ({
            id: sk.id,
            rho: sk.rho,
            key: sk.key,
            tr: tr.slice(),
            shares: sk.shares,
        }));
        return { publicKey, shares };
    }
    /**
     * Full threshold signing protocol (local convenience method).
     *
     * Runs all 3 rounds of the distributed protocol locally. Useful for
     * testing and single-machine deployments. For network-distributed signing,
     * use the round1() -> round2() -> round3() -> combine() methods instead.
     *
     * @param msg - Message to sign
     * @param publicKey - The threshold public key
     * @param shares - At least T threshold key shares
     * @param opts - Optional context
     */
    sign(msg, publicKey, shares, opts) {
        const p = this.#primitives;
        const params = this.params;
        const ctx = opts?.context ?? new Uint8Array(0);
        if (shares.length < params.T) {
            throw new Error(`Need at least ${params.T} shares, got ${shares.length}`);
        }
        abytes(publicKey, p.publicCoder.bytesLen, 'publicKey');
        abytes(msg);
        // Use first T shares
        const activeShares = shares.slice(0, params.T);
        // Compute the active signer bitmask and validate unique IDs
        let act = 0;
        for (const share of activeShares) {
            const bit = 1 << share.id;
            if (act & bit)
                throw new Error(`Duplicate share ID: ${share.id}`);
            act |= bit;
        }
        // Compute mu = H(tr || M) where M = getMessage(msg, ctx)
        const M = getMessage(msg, ctx);
        const mu = shake256
            .create({ dkLen: p.CRH_BYTES })
            .update(activeShares[0].tr)
            .update(M)
            .digest();
        // Main rejection loop
        for (let attempt = 0; attempt < 500; attempt++) {
            // Generate random rhop per party
            const rhops = activeShares.map(() => randomBytes(64));
            // Round 1: Generate commitments
            const allWs = []; // [party][iter][poly_k]
            const allStws = []; // [party][iter]
            for (let pi = 0; pi < activeShares.length; pi++) {
                const { ws, stws } = this.#genCommitment(activeShares[pi], rhops[pi], attempt, params);
                allWs.push(ws);
                allStws.push(stws);
            }
            // Aggregate commitments
            const wfinals = this.#aggregateCommitments(allWs, params);
            // Compute responses per party
            const allZs = []; // [party][iter][poly_l]
            for (let pi = 0; pi < activeShares.length; pi++) {
                const zs = this.#computeResponses(activeShares[pi], act, mu, wfinals, allStws[pi], params);
                allZs.push(zs);
            }
            // Aggregate responses
            const zfinals = this.#aggregateResponses(allZs, params);
            // Combine into signature
            const sig = this.#combine(publicKey, mu, wfinals, zfinals, params);
            if (sig !== null) {
                // H6 fix: zero secret material after successful signing
                for (const stws of allStws)
                    for (const stw of stws)
                        stw.fill(0);
                for (const zs of allZs)
                    for (const z of zs)
                        cleanBytes(z);
                mu.fill(0);
                return sig;
            }
        }
        // H6 fix: zero secret material on failure path too
        mu.fill(0);
        throw new Error('Failed to produce valid threshold signature after 500 attempts');
    }
    /**
     * Round 1: Generate commitment for distributed threshold signing.
     *
     * Each party calls this independently with fresh randomness.
     * The returned commitmentHash (32 bytes) should be broadcast to all parties.
     *
     * @param share - This party's key share
     * @param opts - Optional: nonce (default 0), rhop (default random 64 bytes)
     */
    round1(share, opts) {
        const p = this.#primitives;
        const params = this.params;
        const nonce = opts?.nonce ?? 0;
        let rhop = opts?.rhop;
        if (!rhop)
            rhop = randomBytes(64);
        abytes(rhop, 64, 'rhop');
        const { ws, stws } = this.#genCommitment(share, rhop, nonce, params);
        const commitment = ThresholdMLDSA.#packPolys(ws, p.K, params.K_iter);
        const commitmentHash = this.#hashCommitment(share.tr, share.id, commitment);
        return {
            commitmentHash,
            state: new Round1State(stws, commitment),
        };
    }
    /**
     * Round 2: Receive all commitment hashes, reveal own commitment.
     *
     * After receiving commitment hashes from all active parties, each party
     * stores the hashes (for verification in round 3), computes the message
     * digest mu, and reveals their own packed commitment data.
     *
     * @param share - This party's key share
     * @param activePartyIds - IDs of all participating parties (including this one)
     * @param msg - Message to sign
     * @param round1Hashes - Commitment hashes from all active parties
     * @param round1State - This party's state from round1()
     * @param opts - Optional context
     */
    round2(share, activePartyIds, msg, round1Hashes, round1State, opts) {
        const p = this.#primitives;
        const params = this.params;
        const ctx = opts?.context ?? new Uint8Array(0);
        if (activePartyIds.length < params.T) {
            throw new Error(`Need at least ${params.T} parties, got ${activePartyIds.length}`);
        }
        if (round1Hashes.length !== activePartyIds.length) {
            throw new Error(`Expected ${activePartyIds.length} hashes, got ${round1Hashes.length}`);
        }
        // Validate unique party IDs and compute bitmask
        let act = 0;
        for (const id of activePartyIds) {
            const bit = 1 << id;
            if (act & bit)
                throw new Error(`Duplicate party ID: ${id}`);
            act |= bit;
        }
        // Store hashes for verification in round 3
        const hashes = round1Hashes.map((h) => h.slice());
        // Compute mu = H(tr || getMessage(msg, ctx))
        const M = getMessage(msg, ctx);
        const mu = shake256.create({ dkLen: p.CRH_BYTES }).update(share.tr).update(M).digest();
        return {
            commitment: round1State._commitment.slice(),
            state: new Round2State(hashes, mu, act, [...activePartyIds]),
        };
    }
    /**
     * Round 3: Receive all commitments, verify against hashes, compute partial response.
     *
     * After receiving all parties' commitment reveals, each party:
     * 1. Verifies each commitment matches the hash broadcast in round 1
     * 2. Aggregates all commitments
     * 3. Computes their partial response (z vectors)
     *
     * @param share - This party's key share
     * @param commitments - Packed commitments from all active parties
     * @param round1State - This party's state from round1()
     * @param round2State - This party's state from round2()
     * @returns Packed partial response to broadcast
     */
    round3(share, commitments, round1State, round2State) {
        const p = this.#primitives;
        const params = this.params;
        const { K, L } = p;
        const activePartyIds = round2State._activePartyIds;
        const hashes = round2State._hashes;
        const mu = round2State._mu;
        const act = round2State._act;
        if (commitments.length !== activePartyIds.length) {
            throw new Error(`Expected ${activePartyIds.length} commitments, got ${commitments.length}`);
        }
        // Verify each commitment against stored hash (binding check)
        for (let i = 0; i < commitments.length; i++) {
            const expected = this.#hashCommitment(share.tr, activePartyIds[i], commitments[i]);
            let diff = 0;
            for (let j = 0; j < expected.length; j++)
                diff |= expected[j] ^ hashes[i][j];
            if (diff !== 0) {
                throw new Error(`Commitment hash mismatch for party ${activePartyIds[i]}`);
            }
        }
        // Unpack and aggregate commitments
        const allWs = commitments.map((c) => ThresholdMLDSA.#unpackPolys(c, K, params.K_iter));
        const wfinals = this.#aggregateCommitments(allWs, params);
        // Compute this party's partial response
        const stws = round1State._stws;
        const zs = this.#computeResponses(share, act, mu, wfinals, stws, params);
        return ThresholdMLDSA.#packPolys(zs, L, params.K_iter);
    }
    /**
     * Combine: Aggregate all parties' data and produce a standard FIPS 204 signature.
     *
     * Anyone with the public key can perform this step — it does not require
     * secret key material.
     *
     * @param publicKey - The threshold public key
     * @param msg - Message that was signed
     * @param commitments - Packed commitments from all active parties
     * @param responses - Packed responses from all active parties
     * @param opts - Optional context (must match what was used in round2)
     * @returns Standard FIPS 204 signature, or null if this attempt failed
     */
    combine(publicKey, msg, commitments, responses, opts) {
        const p = this.#primitives;
        const { K, L } = p;
        const params = this.params;
        const ctx = opts?.context ?? new Uint8Array(0);
        abytes(publicKey, p.publicCoder.bytesLen, 'publicKey');
        // Compute mu = H(tr || getMessage(msg, ctx)) where tr = H(publicKey)
        const M = getMessage(msg, ctx);
        const tr = shake256(publicKey, { dkLen: p.TR_BYTES });
        const mu = shake256.create({ dkLen: p.CRH_BYTES }).update(tr).update(M).digest();
        // Unpack and aggregate commitments
        const allWs = commitments.map((c) => ThresholdMLDSA.#unpackPolys(c, K, params.K_iter));
        const wfinals = this.#aggregateCommitments(allWs, params);
        // Unpack and aggregate responses
        const allZs = responses.map((r) => ThresholdMLDSA.#unpackPolys(r, L, params.K_iter));
        const zfinals = this.#aggregateResponses(allZs, params);
        const result = this.#combine(publicKey, mu, wfinals, zfinals, params);
        mu.fill(0);
        return result;
    }
    /**
     * Phase 0: Deterministic DKG setup.
     * Enumerates all bitmasks and their holders for the given (T, N).
     */
    dkgSetup(sessionId) {
        abytes(sessionId, 32, 'sessionId');
        const params = this.params;
        const bitmasks = [];
        const holdersOf = new Map();
        const bitsSet = params.N - params.T + 1;
        let mask = (1 << bitsSet) - 1;
        while (mask < 1 << params.N) {
            bitmasks.push(mask);
            const holders = [];
            for (let i = 0; i < params.N; i++) {
                if (mask & (1 << i))
                    holders.push(i);
            }
            holdersOf.set(mask, holders);
            const c = mask & -mask;
            const r = mask + c;
            mask = (((r ^ mask) >> 2) / c) | r;
        }
        return { bitmasks, holdersOf };
    }
    /**
     * Phase 1: Generate commitments for all entropy.
     *
     * Each party samples rho_i and per-bitmask r_{i,b}, commits via SHAKE256,
     * and broadcasts the commitments. State is kept private.
     *
     * @param partyId - This party's index (0-based)
     * @param sessionId - 32-byte unique session identifier
     * @param opts - Optional: provide deterministic entropy for testing
     */
    dkgPhase1(partyId, sessionId, opts) {
        abytes(sessionId, 32, 'sessionId');
        if (partyId < 0 || partyId >= this.params.N)
            throw new Error(`Invalid partyId: ${partyId}`);
        const { bitmasks } = this.dkgSetup(sessionId);
        const rho = opts?.rho?.slice() ?? randomBytes(32);
        const rhoCommitment = shake256
            .create({ dkLen: 32 })
            .update(ThresholdMLDSA.#DKG_RHO_COMMIT)
            .update(sessionId)
            .update(ThresholdMLDSA.#encodeU8(partyId))
            .update(rho)
            .digest();
        const bitmaskEntropy = new Map();
        const bitmaskCommitments = new Map();
        for (const b of bitmasks) {
            if (!(b & (1 << partyId)))
                continue;
            const r_ib = opts?.bitmaskEntropy?.get(b)?.slice() ?? randomBytes(32);
            bitmaskEntropy.set(b, r_ib);
            const commitment = shake256
                .create({ dkLen: 32 })
                .update(ThresholdMLDSA.#DKG_BSEED_COMMIT)
                .update(sessionId)
                .update(ThresholdMLDSA.#encodeU16LE(b))
                .update(ThresholdMLDSA.#encodeU8(partyId))
                .update(r_ib)
                .digest();
            bitmaskCommitments.set(b, commitment);
        }
        return {
            broadcast: { partyId, rhoCommitment, bitmaskCommitments },
            state: { rho, bitmaskEntropy },
        };
    }
    /**
     * Phase 2: Reveal entropy and prepare private messages for fellow holders.
     *
     * After collecting all Phase 1 broadcasts, each party reveals their rho_i
     * (broadcast) and sends r_{i,b} values to fellow holders (private).
     */
    dkgPhase2(partyId, sessionId, state, allPhase1) {
        abytes(sessionId, 32, 'sessionId');
        const params = this.params;
        if (allPhase1.length !== params.N) {
            throw new Error(`Expected ${params.N} Phase 1 broadcasts, got ${allPhase1.length}`);
        }
        const { bitmasks, holdersOf } = this.dkgSetup(sessionId);
        const broadcast = { partyId, rho: state.rho };
        const privateToHolders = new Map();
        for (const b of bitmasks) {
            if (!(b & (1 << partyId)))
                continue;
            const holders = holdersOf.get(b);
            const r_ib = state.bitmaskEntropy.get(b);
            for (const j of holders) {
                if (j === partyId)
                    continue;
                let msg = privateToHolders.get(j);
                if (!msg) {
                    msg = {
                        fromPartyId: partyId,
                        bitmaskReveals: new Map(),
                    };
                    privateToHolders.set(j, msg);
                }
                msg.bitmaskReveals.set(b, r_ib);
            }
        }
        return { broadcast, privateToHolders };
    }
    /**
     * Phase 2 Finalize + Phase 3: Verify reveals, derive seeds/shares, generate masks.
     *
     * After receiving all Phase 2 broadcasts and private reveals:
     * 1. Verifies all rho commitments
     * 2. Verifies all bitmask seed commitments
     * 3. Derives joint rho, A, and generator assignments
     * 4. Derives bitmask seeds and shares
     * 5. For bitmasks where this party is generator: computes w^b, splits into masks
     */
    dkgPhase2Finalize(partyId, sessionId, state, allPhase1, allPhase2Broadcasts, receivedReveals) {
        const p = this.#primitives;
        const { K, L } = p;
        const params = this.params;
        abytes(sessionId, 32, 'sessionId');
        const { bitmasks, holdersOf } = this.dkgSetup(sessionId);
        // Step 2a: Verify rho commitments
        for (const ph2 of allPhase2Broadcasts) {
            const ph1 = allPhase1.find((x) => x.partyId === ph2.partyId);
            if (!ph1)
                throw new Error(`Missing Phase 1 broadcast for party ${ph2.partyId}`);
            const expected = shake256
                .create({ dkLen: 32 })
                .update(ThresholdMLDSA.#DKG_RHO_COMMIT)
                .update(sessionId)
                .update(ThresholdMLDSA.#encodeU8(ph2.partyId))
                .update(ph2.rho)
                .digest();
            if (!equalBytes(expected, ph1.rhoCommitment)) {
                throw new Error(`Rho commitment mismatch for party ${ph2.partyId}`);
            }
        }
        // Step 2c: Verify bitmask seed commitments
        const revealsByParty = new Map();
        for (const reveal of receivedReveals) {
            revealsByParty.set(reveal.fromPartyId, reveal.bitmaskReveals);
        }
        for (const [fromId, reveals] of revealsByParty) {
            const ph1 = allPhase1.find((x) => x.partyId === fromId);
            if (!ph1)
                throw new Error(`Missing Phase 1 broadcast for party ${fromId}`);
            for (const [b, r_ib] of reveals) {
                const expected = shake256
                    .create({ dkLen: 32 })
                    .update(ThresholdMLDSA.#DKG_BSEED_COMMIT)
                    .update(sessionId)
                    .update(ThresholdMLDSA.#encodeU16LE(b))
                    .update(ThresholdMLDSA.#encodeU8(fromId))
                    .update(r_ib)
                    .digest();
                const committed = ph1.bitmaskCommitments.get(b);
                if (!committed || !equalBytes(expected, committed)) {
                    throw new Error(`Bitmask seed commitment mismatch for party ${fromId}, bitmask ${b}`);
                }
            }
        }
        // Step 2d: Derive joint rho
        const sortedBroadcasts = [...allPhase2Broadcasts].sort((a, b) => a.partyId - b.partyId);
        const rhoHasher = shake256
            .create({ dkLen: 32 })
            .update(ThresholdMLDSA.#DKG_RHO_AGG)
            .update(sessionId);
        for (const ph2 of sortedBroadcasts)
            rhoHasher.update(ph2.rho);
        const rho = rhoHasher.digest();
        // Expand A from rho
        const xof = p.XOF128(rho);
        const A = [];
        for (let i = 0; i < K; i++) {
            const row = [];
            for (let j = 0; j < L; j++)
                row.push(p.RejNTTPoly(xof.get(j, i)));
            A.push(row);
        }
        xof.clean();
        // Generator assignment
        const generatorAssignment = new Map();
        for (const b of bitmasks) {
            const holders = holdersOf.get(b);
            const gRaw = shake256
                .create({ dkLen: 1 })
                .update(ThresholdMLDSA.#DKG_GEN_ASSIGN)
                .update(sessionId)
                .update(rho)
                .update(ThresholdMLDSA.#encodeU16LE(b))
                .digest();
            generatorAssignment.set(b, holders[gRaw[0] % holders.length]);
        }
        // Step 2e: Derive bitmask seeds and shares
        const shares = new Map();
        for (const b of bitmasks) {
            if (!(b & (1 << partyId)))
                continue;
            const holders = holdersOf.get(b);
            // Build seed_b from sorted holder entropy
            const seedHasher = shake256
                .create({ dkLen: 64 })
                .update(ThresholdMLDSA.#DKG_BSEED)
                .update(sessionId)
                .update(ThresholdMLDSA.#encodeU16LE(b));
            for (const h of holders) {
                if (h === partyId) {
                    seedHasher.update(state.bitmaskEntropy.get(b));
                }
                else {
                    const rvls = revealsByParty.get(h);
                    if (!rvls)
                        throw new Error(`Missing reveals from party ${h}`);
                    const r_hb = rvls.get(b);
                    if (!r_hb)
                        throw new Error(`Missing reveal for bitmask ${b} from party ${h}`);
                    seedHasher.update(r_hb);
                }
            }
            const seedB = seedHasher.digest();
            // Derive share
            const s1 = [];
            const s2 = [];
            for (let j = 0; j < L; j++)
                s1.push(this.#deriveUniformLeqEta(seedB, j));
            for (let j = 0; j < K; j++)
                s2.push(this.#deriveUniformLeqEta(seedB, j + L));
            const s1Hat = s1.map((s) => p.NTT.encode(s.slice()));
            const s2Hat = s2.map((s) => p.NTT.encode(s.slice()));
            shares.set(b, { s1, s2, s1Hat, s2Hat });
            cleanBytes(seedB);
        }
        // Phase 3: For bitmasks where this party is generator, compute w^b and split
        const privateToAll = new Map();
        const ownMaskPieces = new Map();
        for (const b of bitmasks) {
            if (generatorAssignment.get(b) !== partyId)
                continue;
            const share = shares.get(b);
            if (!share)
                throw new Error(`Party ${partyId} is generator for bitmask ${b} but doesn't hold it`);
            // w^b = InvNTT(A * s1Hat^b) + s2^b, normalized to [0, Q)
            const wb = [];
            for (let i = 0; i < K; i++) {
                const wi = p.newPoly(N);
                for (let j = 0; j < L; j++) {
                    p.polyAdd(wi, p.MultiplyNTTs(A[i][j], share.s1Hat[j]));
                }
                p.NTT.decode(wi);
                p.polyAdd(wi, share.s2[i]);
                for (let c = 0; c < N; c++)
                    wi[c] = ((wi[c] % Q) + Q) % Q;
                wb.push(wi);
            }
            // Split w^b into N additive masks (residual at gen(b) = partyId)
            const masks = ThresholdMLDSA.#splitVectorK(wb, params.N, partyId);
            // Distribute masks
            for (let j = 0; j < params.N; j++) {
                if (j === partyId) {
                    ownMaskPieces.set(b, masks[j]);
                    continue;
                }
                let msg = privateToAll.get(j);
                if (!msg) {
                    msg = {
                        fromGeneratorId: partyId,
                        maskPieces: new Map(),
                    };
                    privateToAll.set(j, msg);
                }
                msg.maskPieces.set(b, masks[j]);
            }
        }
        return { shares, generatorAssignment, rho, privateToAll, ownMaskPieces };
    }
    /**
     * Phase 4: Aggregate received mask pieces and broadcast R_j.
     *
     * R_j = sum over all bitmasks b of r_{b,j} (mod q)
     */
    dkgPhase4(partyId, bitmasks, generatorAssignment, receivedMasks, ownMaskPieces) {
        const p = this.#primitives;
        const { K } = p;
        // Build lookup: generator -> their mask pieces for this party
        const masksByGenerator = new Map();
        for (const rm of receivedMasks) {
            // Merge from same generator (in case multiple DKGPhase3Private from same generator)
            const existing = masksByGenerator.get(rm.fromGeneratorId);
            if (existing) {
                const merged = new Map(existing);
                for (const [b, piece] of rm.maskPieces)
                    merged.set(b, piece);
                masksByGenerator.set(rm.fromGeneratorId, merged);
            }
            else {
                masksByGenerator.set(rm.fromGeneratorId, rm.maskPieces);
            }
        }
        // R_j = sum over all b of r_{b,j} (mod q)
        const aggregate = [];
        for (let k = 0; k < K; k++)
            aggregate.push(new Int32Array(N));
        for (const b of bitmasks) {
            const gen = generatorAssignment.get(b);
            let maskPiece;
            if (gen === partyId) {
                const own = ownMaskPieces.get(b);
                if (!own)
                    throw new Error(`Missing own mask piece for bitmask ${b}`);
                maskPiece = own;
            }
            else {
                const genMasks = masksByGenerator.get(gen);
                if (!genMasks)
                    throw new Error(`Missing mask pieces from generator ${gen}`);
                const piece = genMasks.get(b);
                if (!piece)
                    throw new Error(`Missing mask piece for bitmask ${b} from generator ${gen}`);
                maskPiece = piece;
            }
            for (let k = 0; k < K; k++)
                p.polyAdd(aggregate[k], maskPiece[k]);
        }
        // Normalize
        for (let k = 0; k < K; k++) {
            for (let c = 0; c < N; c++)
                aggregate[k][c] = p.mod(aggregate[k][c]);
        }
        return { partyId, aggregate };
    }
    /**
     * Finalize: Aggregate all parties' R_j to compute t, derive public key and ThresholdKeyShare.
     *
     * t = sum_j R_j (mod q), then Power2Round, encode public key.
     */
    dkgFinalize(partyId, rho, allPhase4, shares) {
        const p = this.#primitives;
        const { K, TR_BYTES } = p;
        const params = this.params;
        if (allPhase4.length !== params.N) {
            throw new Error(`Expected ${params.N} Phase 4 broadcasts, got ${allPhase4.length}`);
        }
        // t = sum_j R_j (mod q)
        const t = [];
        for (let k = 0; k < K; k++)
            t.push(new Int32Array(N));
        for (const ph4 of allPhase4) {
            for (let k = 0; k < K; k++)
                p.polyAdd(t[k], ph4.aggregate[k]);
        }
        for (let k = 0; k < K; k++) {
            for (let c = 0; c < N; c++)
                t[k][c] = p.mod(t[k][c]);
        }
        // Power2Round(t) -> (t0, t1)
        const t1 = [];
        for (let k = 0; k < K; k++) {
            const { r1 } = p.polyPowerRound(t[k]);
            t1.push(r1);
        }
        // Encode public key
        const publicKey = p.publicCoder.encode([rho, t1]);
        // tr = H(pk)
        const tr = shake256(publicKey, { dkLen: TR_BYTES });
        const share = {
            id: partyId,
            rho: rho.slice(),
            key: randomBytes(32),
            tr,
            shares: shares,
        };
        return { publicKey, share };
    }
    /** Get the byte size of a packed commitment from round1. */
    get commitmentByteLength() {
        return this.params.K_iter * this.#primitives.K * ThresholdMLDSA.#POLY_Q_SIZE;
    }
    /** Get the byte size of a packed response from round3. */
    get responseByteLength() {
        return this.params.K_iter * this.#primitives.L * ThresholdMLDSA.#POLY_Q_SIZE;
    }
    /** Derive a polynomial with coefficients in [-eta, eta] from seed and nonce. */
    #deriveUniformLeqEta(seed, nonce) {
        const p = this.#primitives;
        // Use SHAKE256 as in Go: PolyDeriveUniformLeqEta
        const iv = new Uint8Array(66);
        iv.set(seed.subarray(0, 64));
        iv[64] = nonce & 0xff;
        iv[65] = (nonce >> 8) & 0xff;
        const h = shake256.create({}).update(iv);
        const buf = new Uint8Array(136); // SHAKE-256 rate
        const poly = p.newPoly(N);
        let j = 0;
        while (j < N) {
            h.xofInto(buf);
            for (let i = 0; j < N && i < 136; i++) {
                const t1 = buf[i] & 15;
                const t2 = buf[i] >> 4;
                if (p.ETA === 2) {
                    if (t1 <= 14) {
                        poly[j++] = p.mod(Q + p.ETA - (t1 - Math.floor((205 * t1) >> 10) * 5));
                    }
                    if (j < N && t2 <= 14) {
                        poly[j++] = p.mod(Q + p.ETA - (t2 - Math.floor((205 * t2) >> 10) * 5));
                    }
                }
                else if (p.ETA === 4) {
                    if (t1 <= 2 * p.ETA) {
                        poly[j++] = p.mod(Q + p.ETA - t1);
                    }
                    if (j < N && t2 <= 2 * p.ETA) {
                        poly[j++] = p.mod(Q + p.ETA - t2);
                    }
                }
            }
        }
        return poly;
    }
    /** Recover the combined share for a given active set bitmask. */
    #recoverShare(share, act) {
        const p = this.#primitives;
        const params = this.params;
        const { K, L } = p;
        // Base case: T=N, each party has exactly one share
        if (params.T === params.N) {
            for (const [, s] of share.shares) {
                return {
                    s1Hat: s.s1Hat.map((x) => x.slice()),
                    s2Hat: s.s2Hat.map((x) => x.slice()),
                };
            }
            throw new Error('No shares available');
        }
        const sharing = ThresholdMLDSA.#getSharingPattern(params.T, params.N);
        if (!sharing)
            throw new Error(`No sharing pattern for T=${params.T}, N=${params.N}`);
        // Build permutation mapping active set to reference pattern
        const perm = new Uint8Array(params.N);
        let i1 = 0;
        let i2 = params.T;
        let currenti = 0;
        for (let j = 0; j < params.N; j++) {
            if (j === share.id)
                currenti = i1;
            if ((act & (1 << j)) !== 0) {
                perm[i1++] = j;
            }
            else {
                perm[i2++] = j;
            }
        }
        // Sum shares according to pattern
        const s1Hat = [];
        const s2Hat = [];
        for (let i = 0; i < L; i++)
            s1Hat.push(new Int32Array(N));
        for (let i = 0; i < K; i++)
            s2Hat.push(new Int32Array(N));
        for (const u of sharing[currenti]) {
            // Apply permutation to translate share index
            let u_ = 0;
            for (let i = 0; i < params.N; i++) {
                if ((u & (1 << i)) !== 0) {
                    u_ |= 1 << perm[i];
                }
            }
            const s = share.shares.get(u_);
            if (!s)
                throw new Error(`Missing share for bitmask ${u_}`);
            for (let j = 0; j < L; j++)
                p.polyAdd(s1Hat[j], s.s1Hat[j]);
            for (let j = 0; j < K; j++)
                p.polyAdd(s2Hat[j], s.s2Hat[j]);
        }
        // Normalize
        for (let j = 0; j < L; j++)
            for (let i = 0; i < N; i++)
                s1Hat[j][i] = p.mod(s1Hat[j][i]);
        for (let j = 0; j < K; j++)
            for (let i = 0; i < N; i++)
                s2Hat[j][i] = p.mod(s2Hat[j][i]);
        return { s1Hat, s2Hat };
    }
    /** Generate K_iter commitments for a party. */
    #genCommitment(share, rhop, nonce, params) {
        const p = this.#primitives;
        const { K, L } = p;
        // Expand A
        const xof = p.XOF128(share.rho);
        const A = [];
        for (let i = 0; i < K; i++) {
            const row = [];
            for (let j = 0; j < L; j++)
                row.push(p.RejNTTPoly(xof.get(j, i)));
            A.push(row);
        }
        xof.clean();
        const ws = [];
        const stws = [];
        for (let iter = 0; iter < params.K_iter; iter++) {
            // Sample hyperball
            const stw = ThresholdMLDSA.#sampleHyperball(params.rPrime, params.nu, K, L, rhop, nonce * params.K_iter + iter);
            stws.push(stw);
            // Round to (y, e)
            const { z: y, e } = ThresholdMLDSA.#fvecRound(stw, K, L);
            // w = A*NTT(y) + e (in normal domain)
            const yHat = y.map((s) => p.NTT.encode(s.slice()));
            const w = [];
            for (let i = 0; i < K; i++) {
                const wi = p.newPoly(N);
                for (let j = 0; j < L; j++) {
                    p.polyAdd(wi, p.MultiplyNTTs(A[i][j], yHat[j]));
                }
                // Reduce and InvNTT
                for (let c = 0; c < N; c++)
                    wi[c] = p.mod(wi[c]);
                p.NTT.decode(wi);
                // Add error
                p.polyAdd(wi, e[i]);
                // Normalize
                for (let c = 0; c < N; c++)
                    wi[c] = p.mod(wi[c]);
                w.push(wi);
            }
            ws.push(w);
        }
        return { ws, stws };
    }
    /** Aggregate commitments from all parties. */
    #aggregateCommitments(allWs, params) {
        const p = this.#primitives;
        const { K } = p;
        const wfinals = [];
        for (let iter = 0; iter < params.K_iter; iter++) {
            const wf = [];
            for (let j = 0; j < K; j++) {
                const w = p.newPoly(N);
                for (let pi = 0; pi < allWs.length; pi++) {
                    p.polyAdd(w, allWs[pi][iter][j]);
                }
                for (let c = 0; c < N; c++)
                    w[c] = p.mod(w[c]);
                wf.push(w);
            }
            wfinals.push(wf);
        }
        return wfinals;
    }
    /** Compute commitment hash: SHAKE256(tr || partyId || commitment). */
    #hashCommitment(tr, partyId, commitment) {
        return shake256
            .create({ dkLen: 32 })
            .update(tr)
            .update(new Uint8Array([partyId]))
            .update(commitment)
            .digest();
    }
    /** Compute responses for a party. */
    #computeResponses(share, act, mu, wfinals, stws, params) {
        const p = this.#primitives;
        const { K, L } = p;
        const { s1Hat, s2Hat } = this.#recoverShare(share, act);
        const zs = [];
        for (let iter = 0; iter < params.K_iter; iter++) {
            // Decompose wfinal into (w0, w1)
            const w1 = [];
            for (let j = 0; j < K; j++) {
                w1.push(Int32Array.from(wfinals[iter][j].map((x) => p.HighBits(x))));
            }
            // c_tilde = H(mu || W1Vec.encode(w1))
            const cTilde = shake256
                .create({ dkLen: p.C_TILDE_BYTES })
                .update(mu)
                .update(p.W1Vec.encode(w1))
                .digest();
            // c = SampleInBall(c_tilde), then NTT
            const cHat = p.NTT.encode(p.SampleInBall(cTilde));
            // Compute c*s1 in NTT domain, then InvNTT
            const cs1 = [];
            for (let j = 0; j < L; j++) {
                const t = p.MultiplyNTTs(cHat, s1Hat[j]);
                p.NTT.decode(t);
                // Normalize
                for (let c = 0; c < N; c++)
                    t[c] = p.mod(t[c]);
                cs1.push(t);
            }
            // Compute c*s2 in NTT domain, then InvNTT
            const cs2 = [];
            for (let j = 0; j < K; j++) {
                const t = p.MultiplyNTTs(cHat, s2Hat[j]);
                p.NTT.decode(t);
                for (let c = 0; c < N; c++)
                    t[c] = p.mod(t[c]);
                cs2.push(t);
            }
            // Convert to FVec and add hyperball state
            const csVec = ThresholdMLDSA.#fvecFrom(cs1, cs2, K, L);
            const zf = ThresholdMLDSA.#fvecAdd(csVec, stws[iter]);
            // H1 fix: always execute Round() to avoid timing leak from
            // the acceptance pattern correlating with the secret key.
            const excess = ThresholdMLDSA.#fvecExcess(zf, params.r, params.nu, K, L);
            const { z } = ThresholdMLDSA.#fvecRound(zf, K, L);
            if (excess) {
                // Reject this iteration — push zero vector
                const zeroZ = [];
                for (let j = 0; j < L; j++)
                    zeroZ.push(new Int32Array(N));
                zs.push(zeroZ);
            }
            else {
                zs.push(z);
            }
            // H6 fix: zero intermediate secret values
            csVec.fill(0);
            zf.fill(0);
            cleanBytes(cs1, cs2);
        }
        // H6 fix: zero recovered share
        cleanBytes(s1Hat, s2Hat);
        return zs;
    }
    /** Aggregate responses from all parties. */
    #aggregateResponses(allZs, params) {
        const p = this.#primitives;
        const { L } = p;
        const zfinals = [];
        for (let iter = 0; iter < params.K_iter; iter++) {
            const zf = [];
            for (let j = 0; j < L; j++) {
                const z = p.newPoly(N);
                for (let pi = 0; pi < allZs.length; pi++) {
                    p.polyAdd(z, allZs[pi][iter][j]);
                }
                for (let c = 0; c < N; c++)
                    z[c] = p.mod(z[c]);
                zf.push(z);
            }
            zfinals.push(zf);
        }
        return zfinals;
    }
    /** Combine aggregated commitments and responses into a standard FIPS 204 signature. */
    #combine(publicKey, mu, wfinals, zfinals, params) {
        const p = this.#primitives;
        const { K, L, GAMMA1, GAMMA2, BETA, OMEGA } = p;
        // Decode public key to get (rho, t1)
        const [rho, t1] = p.publicCoder.decode(publicKey);
        // Expand A from rho
        const xof = p.XOF128(rho);
        const A = [];
        for (let i = 0; i < K; i++) {
            const row = [];
            for (let j = 0; j < L; j++)
                row.push(p.RejNTTPoly(xof.get(j, i)));
            A.push(row);
        }
        xof.clean();
        for (let iter = 0; iter < params.K_iter; iter++) {
            const z = zfinals[iter];
            // Check ||z||∞ < γ1 - β
            let exceeds = false;
            for (let j = 0; j < L; j++) {
                if (p.polyChknorm(z[j], GAMMA1 - BETA)) {
                    exceeds = true;
                    break;
                }
            }
            if (exceeds)
                continue;
            // Decompose wfinal into (w0, w1)
            const w0 = [];
            const w1 = [];
            for (let j = 0; j < K; j++) {
                const w0j = p.newPoly(N);
                const w1j = p.newPoly(N);
                for (let c = 0; c < N; c++) {
                    const d = p.decompose(wfinals[iter][j][c]);
                    w0j[c] = d.r0;
                    w1j[c] = d.r1;
                }
                w0.push(w0j);
                w1.push(w1j);
            }
            // c_tilde = H(mu || W1Vec.encode(w1))
            const cTilde = shake256
                .create({ dkLen: p.C_TILDE_BYTES })
                .update(mu)
                .update(p.W1Vec.encode(w1))
                .digest();
            // c = SampleInBall(c_tilde), then NTT
            const cHat = p.NTT.encode(p.SampleInBall(cTilde));
            // Compute Az in NTT domain
            const zNtt = z.map((s) => p.NTT.encode(s.slice()));
            const Az = [];
            for (let i = 0; i < K; i++) {
                const azi = p.newPoly(N);
                for (let j = 0; j < L; j++) {
                    p.polyAdd(azi, p.MultiplyNTTs(A[i][j], zNtt[j]));
                }
                Az.push(azi);
            }
            // Compute Az - 2^d * c * t1
            const result = [];
            for (let i = 0; i < K; i++) {
                const ct12d = p.MultiplyNTTs(p.NTT.encode(p.polyShiftl(t1[i].slice())), cHat);
                result.push(p.NTT.decode(p.polySub(Az[i], ct12d)));
            }
            // Normalize result
            for (let i = 0; i < K; i++) {
                for (let c = 0; c < N; c++)
                    result[i][c] = p.mod(result[i][c]);
            }
            // f = (Az - 2^d*c*t1)_decoded - wfinal
            const f = [];
            for (let j = 0; j < K; j++) {
                const fj = p.newPoly(N);
                for (let c = 0; c < N; c++) {
                    fj[c] = p.mod(result[j][c] - wfinals[iter][j][c]);
                }
                f.push(fj);
            }
            // Check ||f||∞ < γ2
            let fExceeds = false;
            for (let j = 0; j < K; j++) {
                if (p.polyChknorm(f[j], GAMMA2)) {
                    fExceeds = true;
                    break;
                }
            }
            if (fExceeds)
                continue;
            // Compute hint: MakeHint(w0 + f, w1)
            const w0pf = [];
            for (let j = 0; j < K; j++) {
                const w0pfj = p.newPoly(N);
                for (let c = 0; c < N; c++) {
                    w0pfj[c] = p.mod(w0[j][c] + f[j][c]);
                }
                w0pf.push(w0pfj);
            }
            let hintPop = 0;
            const h = [];
            for (let j = 0; j < K; j++) {
                const { v, cnt } = p.polyMakeHint(w0pf[j], w1[j]);
                h.push(v);
                hintPop += cnt;
            }
            if (hintPop > OMEGA)
                continue;
            // Pack signature: [c_tilde, z, h]
            return p.sigCoder.encode([cTilde, z, h]);
        }
        return null;
    }
}
//# sourceMappingURL=threshold-ml-dsa.js.map