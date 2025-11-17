# Build Scripts

This directory contains helper scripts for building and testing the Roughtime project with various configurations.

## Available Scripts

### `build-sanitizers.sh`

Builds and runs tests with **AddressSanitizer** and **UndefinedBehaviorSanitizer** enabled.

**Purpose**: Detect memory errors and undefined behavior:
- Memory leaks
- Use-after-free
- Buffer overflows
- Integer overflows
- Null pointer dereferences
- And more...

**Usage**:
```bash
./scripts/build-sanitizers.sh
```

The script will:
1. Create a separate build directory (`build-sanitizers`)
2. Configure with sanitizers enabled
3. Build the project
4. Run all tests with sanitizer checks

**Note**: Tests may run slower with sanitizers enabled, but this is expected.

### `build-coverage.sh`

Builds and runs tests with **code coverage** instrumentation enabled.

**Purpose**: Generate code coverage reports showing which lines of code are executed by tests.

**Usage**:
```bash
./scripts/build-coverage.sh
```

The script will:
1. Create a separate build directory (`build-coverage`)
2. Configure with coverage enabled
3. Build the project
4. Run all tests
5. Generate coverage reports (requires `lcov`)

**Output**: HTML coverage report in `coverage/index.html`

**Requirements**:
- `lcov` and `genhtml` (install with: `sudo apt-get install lcov`)

**Viewing the report**:
```bash
firefox coverage/index.html
# or
xdg-open coverage/index.html
```

## CMake Build Options

The project supports several build options that can be enabled via CMake:

### ENABLE_SANITIZERS

Enable AddressSanitizer and UndefinedBehaviorSanitizer.

```bash
cmake -DENABLE_SANITIZERS=ON ..
```

### ENABLE_COVERAGE

Enable code coverage instrumentation.

```bash
cmake -DENABLE_COVERAGE=ON ..
```

### ENABLE_LTO

Enable Link Time Optimization for better performance in release builds.

```bash
cmake -DENABLE_LTO=ON -DCMAKE_BUILD_TYPE=Release ..
```

### BUILD_TESTS

Enable/disable test building (default: ON).

```bash
cmake -DBUILD_TESTS=OFF ..  # Disable tests
```

## Manual Build Examples

### Debug Build with Sanitizers:
```bash
mkdir build-debug
cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build . -j$(nproc)
ctest
```

### Release Build with LTO:
```bash
mkdir build-release
cd build-release
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON
cmake --build . -j$(nproc)
```

### Coverage Build:
```bash
mkdir build-coverage
cd build-coverage
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
cmake --build . -j$(nproc)
ctest
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

## CI/CD Integration

These scripts can be integrated into CI/CD pipelines:

**GitHub Actions Example**:
```yaml
- name: Run Sanitizer Tests
  run: ./scripts/build-sanitizers.sh

- name: Generate Coverage Report
  run: ./scripts/build-coverage.sh

- name: Upload Coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    files: ./build-coverage/coverage_filtered.info
```

## Additional Compiler Warnings

The project enables comprehensive compiler warnings by default:
- `-Wall -Wextra -Wpedantic`
- `-Wshadow` (detect variable shadowing)
- `-Wnon-virtual-dtor` (warn about non-virtual destructors)
- `-Wold-style-cast` (detect C-style casts)
- `-Wcast-align` (warn about alignment issues)
- `-Wunused` (warn about unused code)
- `-Woverloaded-virtual` (detect virtual function hiding)
- `-Wconversion` (warn about implicit conversions)
- `-Wsign-conversion` (warn about sign conversions)
- `-Wformat=2` (stricter format string checking)

These warnings help catch potential bugs at compile time.

## Troubleshooting

**Sanitizers report false positives**:
- Check if the issue is in third-party libraries (OpenSSL, glog, etc.)
- Use suppressions file if needed (not recommended for this project)

**Coverage not generated**:
- Ensure `lcov` is installed: `sudo apt-get install lcov`
- Make sure tests are actually running: check `ctest` output

**Build failures with warnings**:
- Fix the warnings - they indicate potential bugs
- Don't disable warnings unless absolutely necessary

## Best Practices

1. **Run sanitizers regularly** during development
2. **Check coverage** to ensure tests cover critical code paths
3. **Fix warnings** before committing code
4. **Use Release builds** with LTO for production deployments
5. **Keep sanitizer builds** separate from regular builds (different directories)
