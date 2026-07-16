# syntax=docker/dockerfile:1.7
FROM rust:1.92-bookworm AS build
ARG GIT_COMMIT=unknown
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
RUN cargo build --locked --release --target wasm32-unknown-unknown -p bench-wasm
RUN GIT_COMMIT=${GIT_COMMIT} cargo build --locked --release -p ishtar-scheduler

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /src/target/release/ishtar-scheduler /app/ishtar-scheduler
COPY --from=build /src/target/wasm32-unknown-unknown/release/bench_wasm.wasm /app/bench_wasm.wasm
COPY profiles /app/profiles
ENV PORT=8080 PROFILE_DIR=/app/profiles WASM_PATH=/app/bench_wasm.wasm
RUN /app/ishtar-scheduler __validate_artifacts
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/ishtar-scheduler"]
