FROM node:12-alpine as webpack

WORKDIR /src

COPY package.json yarn.lock ./
RUN yarn

COPY *.js ./
RUN yarn build --mode production --output-path /js


FROM golang:1.14 as builder

WORKDIR $GOPATH/src/trapdoor

COPY --from=webpack /js js
COPY assets*.go index.html.tmpl go.mod go.sum ./
RUN go generate

COPY *.go ./
COPY .git .git
RUN GIT_COMMIT=$(git rev-parse HEAD) && \
  VERSION=$(git describe --always --match 'v*' | sed 's/^v//') && \
  GO_LDFLAGS="-extldflags -static -s -w -X main.GitCommit=$GIT_COMMIT -X main.Version=$VERSION" && \
  CGO_ENABLED=0 go build -o /trapdoor -ldflags "$GO_LDFLAGS" -tags embed


FROM scratch
MAINTAINER Satoshi Matsumoto <kaorimatz@gmail.com>

WORKDIR /trapdoor

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /trapdoor ./

ENTRYPOINT ["/trapdoor/trapdoor"]
