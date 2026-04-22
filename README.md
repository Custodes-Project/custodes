# Custodes 

Custodes is a modern, blazingly-fast SDC library with sensible defaults built to last. 

## Dependencies

Custodes requires C++17, git (unless downloading the source manually), [CMake](https://cmake.org/download/) version 3.28 or higher, [Doxygen](https://www.doxygen.nl/download.html) for documentation, and a [CMake supported build system](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#manual:cmake-generators(7)) (we recommend [Ninja](https://github.com/ninja-build/ninja/releases) for this.)

### Windows

As Windows lacks a consistent package manager, install the dependencies via the links above.

### Pacman

``` shell
pacman -S gcc git cmake doxygen ninja 
```

### APT

```shell
apt update
apt install g++ git cmake doxygen ninja-build
```

### DNF

```shell
dnf install gcc-c++ git cmake doxygen ninja-build
```

### Homebrew

```shell
brew install clang git cmake doxygen ninja
```

## Building

### Desktop Native

To clone and build with Ninja:
```shell
git clone https://github.com/Custodes-Project/custodes.git --depth=1
cd custodes
cmake -S . -B ./build -G "Ninja Multi-Config"
```

To build the main lib:
```shell
cmake --build ./build
```

To build the docs:
```shell
cmake --build ./build --target=docs
```

You can also specify the build configuration as Debug, Release, MinSizeRel, RelWithDebInfo:
```shell
cmake --build ./build --config=Release
```

To include the GTest suite set the `CSDC_BUILD_TESTING` flag (default is OFF):
```shell
cmake -S . -B ./build -G "Ninja Multi-Config" -DCSDC_BUILD_TESTING=ON
```

To build and execute the test target, ensure the GTest suite is included and build the `CSDC_test` target:

``` shell
cmake --build ./build --target=CSDC_test
ctest
```

## .toml Configuration and Policy Files

Custodes Policy files (CPol) are written in Tom's Obvious Minimal Language (TOML).

### Password Rules (`[passwords]`)

| Key              | Default | Description                                                  |
| ---------------- | ------- | ------------------------------------------------------------ |
| validation_regex | None    | Ignore all other password settings and use provided pattern. |
| min_length       | None    | Minimum allowed password length.                             |
| max_length       | None    | Maximum allowed password length.                             |
| require_capital  | false   | Require a capital letter in password.                        |
| require_number   | false   | Require a number in password.                                |
| require_symbol   | false   | Require a special character in password.                     |
| max_repetition   | None    | Permitted number of concurrent, identical characters. e.g. "aaaa" or "4444" |
| max_sequence     | None    | Permitted number of sequential characters. e.g. "1234" or "abcd" |
| min_entropy      | 0       | Minimum allowed entropy score.                               |
| max_attempts     | None    | Max allowed password entry attempts.                         |

### Logging (`[logging]`)

| Key   | Default | Description                                      |
| ----- | ------- | ------------------------------------------------ |
| level | info    | Set log output level. (debug, info, warn, error) |

## Roles Section (`[roles]`)

The roles section contains one key: `roles`.

The roles key accepts a string which follows a declarative insertion/deletion format:

**Insertion:** `+ <role|document> <user>...`

**Deletion:** `- <role|document> <user>...`

All insertion rules are executed before any deletion rule, regardless of order.  This ensures minimal privilege is granted and additional privileges cannot be granted by later insertions without first removing the deletion.  A deletion on a role, document, or user that has not been added is ignored, this permits explicit blacklisting.