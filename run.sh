#!/bin/bash

# Run the application
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'