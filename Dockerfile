# syntax=docker/dockerfile:1.7
FROM rust:1.92-bookworm AS build
ARG GIT_COMMIT=unknown
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
RUN GIT_COMMIT=${GIT_COMMIT} cargo build --locked --release -p ishtar-scheduler

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /src/target/release/ishtar-scheduler /app/ishtar-scheduler
ENV PORT=8080
USER 65532:65532
RUN /app/ishtar-scheduler __validate_artifacts
EXPOSE 8080
ENTRYPOINT ["/app/ishtar-scheduler"]
