FROM openjdk:8-jre-alpine
MAINTAINER David THIBAU <david.thibau@gmail.com>

ADD ./target/orders-service.jar /app/order-service.jar
CMD ["java", "-Xmx200m", "-jar", "/app/order-service.jar"]

EXPOSE 8888
