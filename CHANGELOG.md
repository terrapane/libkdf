# Change Log

v1.1.0

- Updated APIs for consistency and to make it possible to not pass the optional
  salt parameter to HKDF Extract function.
- Added additional test logic
- Updated dependencies
- Removed pointer arithmetic, migrate to std::span
- Addressed clang-tidy nits

v1.0.11

- Updated dependencies

v1.0.10

- CMake changes
- Updated dependencies

v1.0.9

- Updated dependencies
- CMake change to support downstream unit testing

v1.0.8

- Updated dependencies

v1.0.7

- Updated dependencies
- Enabled stricter compiler warnings

v1.0.6

- Updated dependencies

v1.0.5

- Updated libhash library to 1.0.5

v1.0.4

- Updated dependencies to support FreeBSD builds

v1.0.3

- Updated library dependencies (stf, secutil, and libhash)

v1.0.2

- Updated dependencies (secutil and libhash)

v1.0.1

- Updated secutil to 1.0.1 for better Linux compatibility
- Updated libhash to 1.0.1 to align with same secutil dependency

v1.0.0

- Initial Release
