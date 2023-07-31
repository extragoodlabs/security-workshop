FROM rust:1.71 as build

# create an empty shell project to cache build deps
RUN mkdir -p /app/src && \
    echo 'fn main() {}' > /app/src/main.rs
COPY Cargo.* /app/
WORKDIR /app
RUN cargo build --release && rm src/*.rs

# copy the src and build a release
COPY . .
RUN touch src/main.rs && cargo build --release

# our final base
FROM rust:1.71-slim

# copy the build artifact from the build stage
COPY --from=build /app/target/release/reconciler /usr/local/bin/
COPY settings.json /etc/reconciler.json

ENV APP_CONFIG_FILE=/etc/reconciler.json
CMD ["/usr/local/bin/reconciler"]
