FROM golang:1.24.4-alpine3.22 AS build

WORKDIR /sessionrouter

COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

COPY . .
RUN go build -o srgo .

FROM alpine:3.22 AS run

RUN mkdir /sessionrouter

COPY --from=build /sessionrouter/srgo /sessionrouter/srgo

WORKDIR /sessionrouter

CMD ["./srgo"]




# check README.md for more information on how to build and run the docker image
# docker build -t srgo:latest .
# docker run -d --name srgo -p 5060:5060/udp -p 8080:8080 -e as_sip_udp="#.#.#.#:####" -e server_ipv4="#.#.#.#" -e sip_udp_port="5060" -e http_port="8080" srgo:latest
# docker run -d --name srgo --net=host -e as_sip_udp="#.#.#.#:####" -e server_ipv4="#.#.#.#" -e sip_udp_port="5060" -e http_port="8080" srgo:latest


# Replace #.#.#.#:#### with the IP:Port of Kasuar or NewkahGoSIP
# Replace #.#.#.# with the IP of SR own IP used in SIP and HTTP