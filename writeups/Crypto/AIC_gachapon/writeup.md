# AIC gachapon - Crypto

## Methodology
* **Vulnerability: Cryptographically Insecure PRNG (State Reconstruction)**
The application uses `.NET System.Random`, which relies on the Knuth Subtractive Generator algorithm. This generator is not cryptographically secure; its internal state (a circular buffer of 55 integers) can be mathematically reconstructed by observing a sufficient sequence of previous outputs, allowing an attacker to predict all future random values with 100% accuracy.
* **Steps:**
    1.  **Data Collection** - Capture 6 consecutive "frames" of data to gather enough `sampleInts` (random outputs) to approximate the internal state.
    2.  **Error Correction**: Reverse the floating-point loss of precision by enforcing the Knuth recurrence relation: `State[n] = (State[n-55] - State[n-21]) % MBIG`.
    3.  **Synchronisation**: Reconstruct the full 55-integer seed array and advanced the local RNG state to match the server's current tickId.
    4.  Generate the future winning `redeemCode` locally and submit it to the API!! `Response: {'success': True, 'message': 'Jackpot!', 'tickId': 49, 'flag': 'C2C{244386a6cbea}'}`

## AI Usage

* Manual testing was done to identify the vulnerability and AI was used to speed up exploiting.
* Claude Opus 4.6 was used to generate exploit script.

## 🚩 Proof

Flag: C2C{244386a6cbea}

## AI Script 

```python
#!/usr/bin/env python3
"""
Gachapon CTF solver - C2C 2026

.NET System.Random (Knuth subtractive) RNG prediction.
Recurrence: raw[n] = (raw[n-55] - raw[n-34]) % MBIG

Per-frame RNG consumption (25 calls total):
  [0]  reel0       = Next(10)
  [1]  reel1       = Next(10)
  [2]  reel2       = Next(10)
  [3]  jackpot     = Next(1000000)
  [4..19] sampleInts[0..15] = Next(MBIG)  -- NOTE: may differ from raw by ±1 due to float
  [20..23] sampleBytes = NextBytes(4)      -- raw % 256
  [24] redeemCode  = Next(10000000)

Key insight: Next(MBIG) = int(_internal_sample() * (1.0/MBIG) * MBIG)
Due to float64 precision, this can be _internal_sample() or _internal_sample()-1.
So sampleInts[i] ∈ {raw[i], raw[i]-1}, meaning raw[i] ∈ {sampleInts[i], sampleInts[i]+1}.
"""

import requests
import sys
import time
import itertools

MBIG = 2147483647
CALLS_PER_FRAME = 25


def is_lossy(x):
    """Check if Next(MBIG) would lose precision for this _internal_sample value x."""
    return int(x * (1.0 / MBIG) * MBIG) != x


class DotNetRandom:
    """Faithful .NET System.Random emulation."""
    def __init__(self):
        self._seed_array = [0] * 56
        self._inext = 0
        self._inextp = 0

    def _internal_sample(self):
        inext = self._inext + 1
        if inext > 55: inext = 1
        inextp = self._inextp + 1
        if inextp > 55: inextp = 1
        num = self._seed_array[inext] - self._seed_array[inextp]
        if num == MBIG: num -= 1
        if num < 0: num += MBIG
        self._seed_array[inext] = num
        self._inext = inext
        self._inextp = inextp
        return num

    def _sample(self):
        return self._internal_sample() * (1.0 / MBIG)

    def next_int(self, max_val):
        return int(self._sample() * max_val)

    def next_bytes(self, count):
        return bytes([self._internal_sample() % 256 for _ in range(count)])

    def generate_frame(self):
        reel0 = self.next_int(10)
        reel1 = self.next_int(10)
        reel2 = self.next_int(10)
        jackpot = self.next_int(1000000)
        sample_ints = [self.next_int(MBIG) for _ in range(16)]
        sample_bytes = self.next_bytes(4)
        redeem_code = self.next_int(10000000)
        return {
            'reels': [reel0, reel1, reel2],
            'jackpot': jackpot,
            'sampleInts': sample_ints,
            'sampleBytesHex': sample_bytes.hex(),
            'redeemCode': redeem_code,
        }


def make_rng_at_offset(outputs_55, offset):
    rng = DotNetRandom()
    for i in range(55):
        pos = (offset + i - 1) % 55 + 1
        rng._seed_array[pos] = outputs_55[i]
    rng._inext = (offset + 53) % 55 + 1
    rng._inextp = rng._inext + 21
    if rng._inextp > 55:
        rng._inextp -= 55
    return rng


def clone_rng(rng):
    r = DotNetRandom()
    r._seed_array = list(rng._seed_array)
    r._inext = rng._inext
    r._inextp = rng._inextp
    return r


def try_reconstruct(raw_candidates, validation_observed, n_raw):
    """
    raw_candidates: list of 55 values, each either exact or needing +1.
    We know observed[i] = raw[i] or raw[i]-1, so raw[i] = observed[i] or observed[i]+1.
    
    Try to find the correct combination by checking recurrence consistency and
    validating against subsequent observed values.
    
    n_raw: total number of raw outputs we have (75), for validation purposes.
    validation_observed: observed sampleInt values for positions 55..n_raw-1
    """
    # First try: assume all observed values are exact (raw = observed)
    outputs_55 = list(raw_candidates[:55])
    
    # Find which positions COULD be lossy (observed might be raw-1)
    lossy_positions = []
    for i in range(55):
        if is_lossy(outputs_55[i] + 1):
            # If raw were outputs_55[i]+1, Next(MBIG) would produce outputs_55[i]
            lossy_positions.append(i)
    
    def check_candidate(candidate_55):
        """Check if this candidate produces predictions matching validation data."""
        for offset in range(1, 56):
            rng = make_rng_at_offset(candidate_55, offset)
            test_rng = clone_rng(rng)
            match = True
            for i in range(len(validation_observed)):
                raw_pred = test_rng._internal_sample()
                obs_pred = int(raw_pred * (1.0 / MBIG) * MBIG)
                if obs_pred != validation_observed[i]:
                    match = False
                    break
            if match:
                return offset, rng
        return None, None
    
    # Try all-exact
    offset, rng = check_candidate(outputs_55)
    if offset is not None:
        return offset, rng, outputs_55
    
    # Try flipping one position at a time
    print(f"[*] All-exact failed. Trying single flips ({len(lossy_positions)} lossy positions)...")
    for pos in lossy_positions:
        candidate = list(outputs_55)
        candidate[pos] += 1
        offset, rng = check_candidate(candidate)
        if offset is not None:
            print(f"[*] Fixed position {pos}: {outputs_55[pos]} -> {candidate[pos]}")
            return offset, rng, candidate
    
    # Try all positions (not just pre-identified lossy ones)
    print(f"[*] Trying all single flips...")
    for pos in range(55):
        if pos in lossy_positions:
            continue
        candidate = list(outputs_55)
        candidate[pos] += 1
        offset, rng = check_candidate(candidate)
        if offset is not None:
            print(f"[*] Fixed position {pos}: {outputs_55[pos]} -> {candidate[pos]}")
            return offset, rng, candidate
    
    # Try flipping two positions
    print(f"[*] Trying double flips...")
    all_positions = list(range(55))
    for p1, p2 in itertools.combinations(all_positions, 2):
        candidate = list(outputs_55)
        candidate[p1] += 1
        candidate[p2] += 1
        offset, rng = check_candidate(candidate)
        if offset is not None:
            print(f"[*] Fixed positions {p1},{p2}")
            return offset, rng, candidate
    
    return None, None, None


def solve(base_url):
    base_url = base_url.rstrip('/')

    print("[*] Fetching recent frames...")
    resp = requests.get(f"{base_url}/api/recent/30", timeout=10)
    frames = resp.json()
    print(f"[*] Got {len(frames)} frames")

    if len(frames) < 6:
        wait = (6 - len(frames)) * 2 + 4
        print(f"[!] Need at least 6 frames, waiting {wait}s...")
        time.sleep(wait)
        resp = requests.get(f"{base_url}/api/recent/30", timeout=10)
        frames = resp.json()
        print(f"[*] Got {len(frames)} frames")

    frames.sort(key=lambda f: f['tickId'])

    # Find longest consecutive run
    best_run = [frames[0]]
    current_run = [frames[0]]
    for i in range(1, len(frames)):
        if frames[i]['tickId'] == current_run[-1]['tickId'] + 1:
            current_run.append(frames[i])
        else:
            current_run = [frames[i]]
        if len(current_run) > len(best_run):
            best_run = list(current_run)
    
    if len(best_run) < 6:
        print(f"[!] Need at least 6 consecutive frames, best run: {len(best_run)}")
        return

    use_frames = best_run[-6:]
    print(f"[*] Using 6 consecutive frames: tickIds {[f['tickId'] for f in use_frames]}")

    si = [f['sampleInts'] for f in use_frames]
    
    observed = [None] * 75  # approximate raw values
    
    # Direct sampleInts for frames 2,3,4
    for f_idx, f_uf in enumerate([2, 3, 4]):
        base = 25 * f_idx
        for j in range(16):
            observed[base + 4 + j] = si[f_uf][j]
    
    # Positions 0-10 using gap formula: raw[p+21] = (raw[p] - raw[p+55]) % MBIG
    # Frame 2: raw[i] = (si[1][i] - si[3][i+5]) % MBIG
    for i in range(11):
        observed[i] = (si[1][i] - si[3][i + 5]) % MBIG
    # Frame 3: raw[25+i] = (si[2][i] - si[4][i+5]) % MBIG
    for i in range(11):
        observed[25 + i] = (si[2][i] - si[4][i + 5]) % MBIG
    # Frame 4: raw[50+i] = (si[3][i] - si[5][i+5]) % MBIG
    for i in range(11):
        observed[50 + i] = (si[3][i] - si[5][i + 5]) % MBIG
    
    # Tails: raw[20+m] = (si[0][11+m] - si[1][7+m]) % MBIG, etc.
    for m in range(5):
        observed[20 + m] = (si[0][11 + m] - si[1][7 + m]) % MBIG
    for m in range(5):
        observed[45 + m] = (si[1][11 + m] - si[2][7 + m]) % MBIG
    for m in range(5):
        observed[70 + m] = (si[2][11 + m] - si[3][7 + m]) % MBIG
    
    assert all(v is not None for v in observed), "Missing values!"
    print("[*] Built approximate raw output sequence (75 values)")
    
    
    block_55 = observed[:55]
    validation = observed[55:75]
    
    # Categorize positions by type
    direct_positions = set()
    for f_idx in range(3):
        base = 25 * f_idx
        for j in range(16):
            direct_positions.add(base + 4 + j)
    
    gap_positions = set(range(75)) - direct_positions
    
    print(f"[*] Direct sampleInt positions in block: {len([p for p in range(55) if p in direct_positions])}")
    print(f"[*] Gap-filled positions in block: {len([p for p in range(55) if p in gap_positions])}")
    
    errors = []
    for n in range(55, 75):
        expected = (observed[n - 55] - observed[n - 34]) % MBIG
        if observed[n] != expected:
            diff = observed[n] - expected
            errors.append((n, expected, observed[n], diff))
    
    print(f"[*] Recurrence errors: {len(errors)}")
    for n, exp, got, diff in errors:
        src1 = n - 55
        src2 = n - 34
        s1_type = "D" if src1 in direct_positions else "G"
        s2_type = "D" if src2 in direct_positions else "G"
        n_type = "D" if n in direct_positions else "G"
        print(f"    n={n}({n_type}): src1={src1}({s1_type}) src2={src2}({s2_type}) diff={diff}")
    
    if not errors:
        print("[✓] All recurrence checks pass! Using approximate values as exact.")
    else:
        print("[*] Attempting systematic error correction...")
    
    # Try state reconstruction with the approximate block, systematically flipping values
    print("[*] Trying state reconstruction...")
    
    # For validation, convert observed to what Next(MBIG) would produce
    validation_si = observed[55:75]  # These positions include both direct and gap-filled
    # For positions 55..74: 
    #   positions 54..69 in frame 4 → base 50, so 54-50=4 through 69-50=19 → sampleInts (direct)
    #   positions 70..74 → frame 4 tail (gap-filled)
    #   positions 55..59 → actually frame 3 sampleInts? Let me re-check.
    #   raw[55..74] covers frame 3 pos 5..24 and frame 4 pos 0..24... wait.
    #   raw[0..24] = frame 2, raw[25..49] = frame 3, raw[50..74] = frame 4
    #   So raw[55] = frame 4 position 5 = sampleInts[1] (direct). 
    #   raw[55..69] = frame 4 positions 5..19 = sampleInts[1..15] (direct).
    #   raw[70..74] = frame 4 tail (gap-filled).
    
    # For validation we only use direct sampleInt positions where we know 
    # observed = int(raw * (1.0/MBIG) * MBIG)
    val_direct_indices = []  # indices into validation array (0..19) that are direct sampleInts
    for i in range(20):
        global_pos = 55 + i
        if global_pos in direct_positions:
            val_direct_indices.append(i)
    
    print(f"[*] Validation positions (direct sampleInts): {len(val_direct_indices)} out of 20")
    
    def validate_rng(rng, n_check=None):
        """Check if rng's next outputs match validation data at direct positions."""
        if n_check is None:
            n_check = len(val_direct_indices)
        test_rng = clone_rng(rng)
        outputs = []
        for i in range(20):
            raw_val = test_rng._internal_sample()
            outputs.append(raw_val)
        
        for idx in val_direct_indices[:n_check]:
            raw_val = outputs[idx]
            obs_val = int(raw_val * (1.0 / MBIG) * MBIG)
            if obs_val != validation_si[idx]:
                return False
        return True
    
    def try_candidate(candidate_55):
        """Try all 55 offsets for this candidate, return (offset, rng) if valid."""
        for offset in range(1, 56):
            rng = make_rng_at_offset(candidate_55, offset)
            if validate_rng(rng):
                return offset, rng
        return None, None
    
    # Attempt 1: all exact
    print("[*] Attempt 1: all values exact...")
    offset, rng = try_candidate(block_55)
    
    if offset is None:
        # Attempt 2: flip each position one at a time (+1)
        print("[*] Attempt 2: single position flips (+1)...")
        for pos in range(55):
            candidate = list(block_55)
            candidate[pos] = (candidate[pos] + 1) % (MBIG + 1)
            offset, rng = try_candidate(candidate)
            if offset is not None:
                print(f"[✓] Fixed by flipping position {pos}")
                block_55 = candidate
                break
    
    if offset is None:
        # Attempt 3: flip each position by -1
        print("[*] Attempt 3: single position flips (-1)...")
        original = list(block_55)
        for pos in range(55):
            candidate = list(original)
            candidate[pos] = (candidate[pos] - 1) % MBIG
            offset, rng = try_candidate(candidate)
            if offset is not None:
                print(f"[✓] Fixed by flipping position {pos} by -1")
                block_55 = candidate
                break
    
    if offset is None:
        # Attempt 4: double flips (+1)
        print("[*] Attempt 4: double position flips (+1)...")
        original = list(block_55)
        for p1 in range(55):
            for p2 in range(p1 + 1, 55):
                candidate = list(original)
                candidate[p1] += 1
                candidate[p2] += 1
                offset, rng = try_candidate(candidate)
                if offset is not None:
                    print(f"[✓] Fixed by flipping positions {p1},{p2}")
                    block_55 = candidate
                    break
            if offset is not None:
                break
    
    if offset is None:
        # Attempt 5: mixed flips (+1, -1)
        print("[*] Attempt 5: mixed double flips...")
        original = list(block_55)
        for p1 in range(55):
            for p2 in range(55):
                if p1 == p2:
                    continue
                candidate = list(original)
                candidate[p1] += 1
                candidate[p2] -= 1
                if candidate[p2] < 0:
                    candidate[p2] += MBIG
                offset, rng = try_candidate(candidate)
                if offset is not None:
                    print(f"[✓] Fixed by +1@{p1}, -1@{p2}")
                    block_55 = candidate
                    break
            if offset is not None:
                break

    if offset is None:
        print("[!] FATAL: Could not reconstruct RNG state")
        return
    
    print(f"[✓] State reconstructed! offset={offset}")
    
    # ── Advance to current frame and predict ──
    # rng is now ready to produce raw[55] (which is frame 4 position 5).
    # We need to advance to the end of frame 4 (15 more calls from pos 5 to pos 24).
    # Wait: raw[55..74] = 20 values = frame 4 positions 5..24.
    for _ in range(20):
        rng._internal_sample()
    # Now rng is at the start of the frame AFTER use_frames[4] (= frame 5)
    
    last_known_tick = use_frames[4]['tickId']
    
    # Sync with server
    print(f"[*] Last known tick: {last_known_tick}")
    resp = requests.get(f"{base_url}/api/frame", timeout=10)
    current = resp.json()
    current_tick = current['tickId']
    print(f"[*] Current tick: {current_tick}")
    
    frames_ahead = current_tick - last_known_tick
    print(f"[*] Advancing RNG by {frames_ahead} frames...")
    for _ in range(frames_ahead * CALLS_PER_FRAME):
        rng._internal_sample()
    
    # Verify against current frame
    # Note: sampleInts = Next(MBIG) = int(raw * (1.0/MBIG) * MBIG)
    # Python and C# may produce slightly different float results, so allow ±1 tolerance
    def si_match(predicted_si, actual_si):
        return all(abs(p - a) <= 1 for p, a in zip(predicted_si, actual_si))
    
    for adj in range(0, 5):
        verify_rng = clone_rng(rng)
        if adj > 0:
            for _ in range(adj * CALLS_PER_FRAME):
                verify_rng._internal_sample()
        pred = verify_rng.generate_frame()
        if si_match(pred['sampleInts'], current['sampleInts']):
            print(f"[✓] Prediction matches current frame! (adj={adj})")
            if adj > 0:
                for _ in range(adj * CALLS_PER_FRAME):
                    rng._internal_sample()
            break
    else:
        # Try negative adjustments
        for adj in range(1, 5):
            re_rng = make_rng_at_offset(block_55, offset)
            for _ in range(20):
                re_rng._internal_sample()
            for _ in range((frames_ahead - adj) * CALLS_PER_FRAME):
                re_rng._internal_sample()
            verify_rng = clone_rng(re_rng)
            pred = verify_rng.generate_frame()
            if si_match(pred['sampleInts'], current['sampleInts']):
                print(f"[✓] Prediction matches current frame! (adj=-{adj})")
                rng = re_rng
                break
        else:
            print("[!] Could not match current frame")
            print(f"    Predicted si[0:3]: {pred['sampleInts'][:3]}")
            print(f"    Actual si[0:3]:    {current['sampleInts'][:3]}")
            return
    
    # Consume current frame
    rng.generate_frame()
    
    # Predict and submit
    for attempt in range(5):
        next_frame = rng.generate_frame()
        target_tick = current_tick + 1 + attempt
        redeem_code = next_frame['redeemCode']
        
        print(f"\n[*] Prediction for tick {target_tick}: redeem={redeem_code} reels={next_frame['reels']}")
        
        # Wait for target tick
        print(f"[*] Waiting for tick {target_tick}...")
        while True:
            time.sleep(0.3)
            resp = requests.get(f"{base_url}/api/frame", timeout=10)
            frame = resp.json()
            if frame['tickId'] >= target_tick:
                break
        
        if frame['tickId'] == target_tick and not si_match(next_frame['sampleInts'], frame['sampleInts']):
            print(f"[!] Prediction WRONG for tick {target_tick}")
            continue
        elif frame['tickId'] == target_tick:
            print(f"[✓] Prediction verified!")
        
        print(f"[*] Submitting code {redeem_code} for tick {target_tick}...")
        resp = requests.post(f"{base_url}/api/redeem", json={
            'tickId': target_tick,
            'code': redeem_code,
        }, timeout=10)
        
        result = resp.json()
        print(f"[*] Response: {result}")
        
        if result.get('success'):
            flag = result.get('flag', '')
            print(f"\n{'='*60}")
            print(f"[🚩] FLAG: {flag}")
            print(f"{'='*60}")
            return
        
        msg = result.get('message', '')
        if 'Wrong tick' in msg:
            current_tick = frame['tickId']
            continue
        elif 'Wrong code' in msg:
            print("[!] Wrong code - RNG prediction error")
            return
    
    print("[!] Failed after 5 attempts")

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://challenges.1pc.tf:30910'
    solve(url)
```