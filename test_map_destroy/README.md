# Map Destruction Test Programs

This directory contains test programs for verifying BPF Map destruction tracking in HVMI.

## Test Programs

### 1. test_map_destroy_simple.c
**Purpose**: Test simple map destruction (no pin)

**Expected behavior**:
- Create map → `[luckybird] MAP_CREATE: map object created`
- close(fd) → `[luckybird] security_bpf_map_free: map = 0x..., id = ...`
- Destruction confirmed → `[luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free`

### 2. test_map_destroy_pinned.c
**Purpose**: Test map destruction with pin/unpin

**Expected behavior**:
- Create map → `[luckybird] MAP_CREATE: map object created`
- Pin map → `[luckybird] OBJ_PIN: map pinned`
- close(fd) → **NO** `security_bpf_map_free` (pin holds reference)
- unlink(pin) → `[luckybird] security_bpf_map_free: map = 0x..., id = ...`
- Destruction confirmed → `[luckybird] Map destroyed: MapGva = 0x..., id = ..., source = security_bpf_map_free`

### 3. test_map_destroy_multi.c
**Purpose**: Test multiple map destruction (verify deduplication)

**Expected behavior**:
- Create 3 maps
- Close all 3 fds
- Each triggers independent `security_bpf_map_free`
- Verify MapId matching works correctly
- Verify no duplicate destruction logs

### 4. test_map_destroy_stress.c
**Purpose**: Stress test (100 maps)

**Expected behavior**:
- Rapidly create and destroy 100 maps
- Verify all destruction events are tracked
- Verify no duplicate destruction logs
- Verify no log spam (TRACE level works correctly)

## Building

```bash
# Build all test programs
make

# Clean build artifacts
make clean

# Show help
make help
```

## Running Tests

```bash
# Run tests in order
sudo ../build/test_map_destroy_simple
sudo ../build/test_map_destroy_pinned
sudo ../build/test_map_destroy_multi
sudo ../build/test_map_destroy_stress
```

## Verification Checklist

For each test, verify the following in HVMI logs:

### test_map_destroy_simple
- [ ] Map created with MapGva and MapId
- [ ] security_bpf_map_free called
- [ ] Map destroyed with source=security_bpf_map_free
- [ ] DestroyTime != 0

### test_map_destroy_pinned
- [ ] Map created and pinned
- [ ] close(fd) did NOT trigger security_bpf_map_free
- [ ] unlink(pin) triggered security_bpf_map_free
- [ ] Map destroyed with source=security_bpf_map_free
- [ ] DestroyTime != 0

### test_map_destroy_multi
- [ ] 3 maps created with different MapGva/MapId
- [ ] 3 independent security_bpf_map_free events
- [ ] 3 independent Map destroyed logs
- [ ] No duplicate destruction (DestroyTime deduplication works)

### test_map_destroy_stress
- [ ] 100 MAP_CREATE events logged
- [ ] 100 security_bpf_map_free events logged
- [ ] 100 Map destroyed events logged
- [ ] No duplicate destruction (check DestroyTime deduplication)
- [ ] No log spam (TRACE level should not flood console)
- [ ] No memory leaks (check gLixBpfMapObjects list size)

## Expected Log Format

All logs should follow this format:

```
[luckybird] MAP_CREATE: map object created (MapGva = 0x..., id = ...)
[luckybird] security_bpf_map_free: map = 0x..., id = ...
[luckybird] Map destroyed: MapGva = 0x..., id = ..., type = ..., source = security_bpf_map_free
```

## Notes

- All tests require root privileges (sudo)
- Tests include sleep() calls to give HVMI time to process events
- Pin test requires /sys/fs/bpf to be mounted
- Stress test may take 10-20 seconds to complete
