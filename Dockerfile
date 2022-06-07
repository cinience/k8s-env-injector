#FROM golang:1.17-buster as build
#
#WORKDIR /go/src/app
#ADD . /go/src/app
#RUN go get -u -t ./...
#RUN go env -w GOPROXY=https://goproxy.cn,direct
#RUN CGO_ENABLED=0 GOOS=linux GO111MODULE="on" go build -a -installsuffix cgo -o /go/bin/app/k8s-env-injector .
#
#FROM gcr.io/distroless/static
#
#COPY --from=build /go/bin/app /
#ENTRYPOINT ["./k8s-env-injector"]
#

FROM golang:alpine3.11 as build
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk --no-cache add git
WORKDIR /go/src/app
ADD . /go/src/app
#RUN go get -u -t ./...
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE="on" go build -a -installsuffix cgo -o /go/bin/app/k8s-env-injector .


# 第二阶段构建
FROM alpine:3
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk --no-cache add ca-certificates openssl tzdata curl

ENV TZ=Asia/Shanghai
COPY --from=build /go/bin/app /
ENTRYPOINT ["./k8s-env-injector"]
