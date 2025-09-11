# Dockerfile for universalregistrar/driver-did-btcr2

FROM maven:3-eclipse-temurin-21-alpine AS build
MAINTAINER Markus Sabadello <markus@danubetech.com>

# build driver-did-btcr2

ADD pom.xml /opt/driver-did-btcr2/
RUN cd /opt/driver-did-btcr2/ && mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.1:go-offline
ADD . /opt/driver-did-btcr2/
RUN cd /opt/driver-did-btcr2/ && mvn clean package -P war -N -DskipTests

# build image

FROM jetty:12.0.18-jre21-eclipse-temurin
MAINTAINER Markus Sabadello <markus@danubetech.com>

# variables

ENV uniregistrar_driver_did_btcr2_bitcoinConnections=bitcoin;bitcoind;testnet3;bitcoind;signet;esploraelectrsrest;mutinynet;esploraelectrsrest
ENV uniregistrar_driver_did_btcr2_bitcoinConnectionsUrls=bitcoin;http://user:pass@localhost:8332/;testnet3;http://user:pass@localhost:18332/;signet;https://mempool.space/signet/api/;mutinynet;https://mutinynet.com/api/
ENV uniregistrar_driver_did_btcr2_bitcoinConnectionsCerts=bitcoin;;testnet3;;signet;;mutinynet;
ENV uniregistrar_driver_did_btcr2_genesisHashes=bitcoin;6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000;testnet3;43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000;signet;f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000;mutinynet;f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000
ENV uniregistrar_driver_did_btcr2_ipfs=/ip4/127.0.0.1/tcp/5001

# copy from build stage

COPY --from=build --chown=jetty /opt/driver-did-btcr2/target/*.war /var/lib/jetty/webapps/ROOT.war

# done

EXPOSE 9080
RUN java -Djetty.http.port=9080 -jar "$JETTY_HOME/start.jar" --add-modules=ee10-webapp,ee10-deploy,ee10-jsp,ee10-jstl
CMD java -Djetty.http.port=9080 -jar "$JETTY_HOME/start.jar"
