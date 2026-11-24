#!/bin/bash
# Bootstrap Gradle wrapper without committing binaries (e.g., gradle-wrapper.jar)
# This ensures reproducible builds using a pinned Gradle version.

set -e

GRADLE_VERSION="8.5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR" || exit 1

echo "Generating Gradle wrapper $GRADLE_VERSION..."
# The 'gradle' command is provided by gradle/actions/setup-gradle in CI, 
# or a local Gradle installation for developers.
gradle wrapper --gradle-version "$GRADLE_VERSION" --distribution-type bin

echo "Gradle wrapper generated successfully at $PROJECT_DIR/gradlew"
