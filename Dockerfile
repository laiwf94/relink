# syntax=docker/dockerfile:1
FROM rust:1.99-slim-trixie AS build
WORKDIR /src
# Dependencies first, against stub sources, so source edits reuse the layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/relink-core/Cargo.toml crates/relink-core/
COPY crates/relink-server/Cargo.toml crates/relink-server/
COPY crates/relink-edge/Cargo.toml crates/relink-edge/
RUN for c in relink-core relink-server relink-edge; do mkdir -p crates/$c/src; touch crates/$c/src/lib.rs; done \
    && echo 'fn main() {}' > crates/relink-server/src/main.rs \
    && mkdir -p crates/relink-server/benches && echo 'fn main() {}' > crates/relink-server/benches/hot_path.rs \
    && cargo build --release --locked -p relink-server --bin relink \
    && rm -rf crates/*/src
COPY crates ./crates
RUN touch crates/*/src/lib.rs crates/relink-server/src/main.rs \
    && cargo build --release --locked -p relink-server --bin relink

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/relink /relink
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/relink"]
