FROM rust:1.82-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/sa-mcp /usr/local/bin/sa-mcp
COPY --from=build /app/config /config
ENV MCP_TOOLS_JSON=/config/tools.json MCP_PROMPTS_JSON=/config/prompts.json MCP_SERVER_JSON=/config/server.json
EXPOSE 8788
CMD ["sa-mcp", "--transport", "http", "--listen", "0.0.0.0:8788"]
