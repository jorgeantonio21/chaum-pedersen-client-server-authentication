# Use the official Rust image
FROM rust:1.73

# Install protoc dependencies
RUN apt-get update \
    && apt-get install -y protobuf-compiler libprotobuf-dev

# Create a working directory
WORKDIR /usr/chaum-pedersen/

# Copy the client code, as well as chaum-pedersen and proto dependencies
COPY ./client/ ./client/
COPY ./chaum-pedersen/ ./chaum-pedersen/
COPY ./proto/ ./proto

# Build the project
RUN cd chaum-pedersen && cargo build --release && cd ..
RUN cd client && cargo build --release && cd ..

# Set default values for your variables
ENV COMMAND_NAME register
ENV MY_NAME nillion
ENV MY_PASSWORD is_safe_no_worries

# Command to run the application
CMD sh -c "RUST_LOG=info cargo run $COMMAND_NAME --name $MY_NAME --password $MY_PASSWORD"
