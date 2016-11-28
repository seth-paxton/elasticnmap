FROM alpine
RUN apk update && apk upgrade
RUN apk add nmap
ENTRYPOINT ["nmap"]
