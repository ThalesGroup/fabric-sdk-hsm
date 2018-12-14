#!/bin/bash

###########################################################################
# This script generates certificates and private keys for Admin users to be
# used to run the end-2-end integration test with a SafeNet Luna HSM.
# It uses fabric-ca-client to generate key pairs in the HSM and to
# generate a certificate signing request.
# Certificates are signed/created using openssl.
##########################################################################

cd ./fabric-sdk-java/src/test/fixture/sdkintegration/e2e-2Orgs/v1.3

CRYPTO_CONFIG=$PWD/crypto-config
ROOT=$PWD

BCCSP_DEFAULT=PKCS11

check_error() {
  if [ $? -ne 0 ]; then
    echo "ERROR:  Something went wrong!"
    exit 1
  fi
}

#Signs a certificate from the certificate signing request for a MSP using openssl
signcsr() {
  MSP=$1
  CN=$2
  CA_MSP=$3
  CA_NAME=$4
  CA_KEY=$CA_MSP/$(basename $(find $CA_MSP -name "*_sk"))
  CA_CERT=$CA_MSP/ca.$CA_NAME-cert.pem
  CSR=$MSP/signcerts/$CN.csr
  CERT=$MSP/signcerts/$CN-cert.pem

  openssl x509 -req -SHA256 -days 3650 -in $CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CERT
  check_error
}

#Generates an MSP directory by creating a certificate signing request using
#"fabric-ca-client gencsr" and generates the signing certificate
genmsp() {
  ORG_DIR=$1
  ORG_NAME=$2
  NODE_DIR=$3
  NODE_NAME=$4
  CN=${NODE_NAME}${ORG_NAME}
  CA_PATH=$CRYPTO_CONFIG/$ORG_DIR/$ORG_NAME
  NODE_PATH=$CA_PATH/$NODE_DIR/$CN/msp
  MSP=$NODE_PATH

  for dir in signcerts keystore cacerts; do
    if [ -d "$MSP/$dir" ]; then
      rm -rf $MSP/$dir
    fi
    mkdir -p $MSP/$dir
  done

  echo $LABEL
  export FABRIC_CA_CLIENT_BCCSP_DEFAULT=$BCCSP_DEFAULT
  export FABRIC_CA_CLIENT_BCCSP_PKCS11_LABEL=$PKCS11_LABEL
  export FABRIC_CA_CLIENT_BCCSP_PKCS11_PIN=$PKCS11_PIN
  fabric-ca-client gencsr --csr.cn $CN --mspdir $MSP
  check_error

  signcsr $MSP $CN $CA_PATH/ca $ORG_NAME

  cp $CA_PATH/ca/ca.$ORG_NAME-cert.pem $MSP/cacerts

  check_error

}

#Copies the Admin user cert to the nodes msp/admincerts directory
copy_admin_cert_node() {
  ORG_DIR=$1
  ORG_NAME=$2
  NODE_DIR=$3
  NODE_NAME=$4
  CN=$NODE_NAME.$ORG_NAME
  CA_PATH=$CRYPTO_CONFIG/$ORG_DIR/$ORG_NAME
  NODE_PATH=$CA_PATH/$NODE_DIR/$CN
  MSP=$NODE_PATH
  ADMIN_CN=Admin@$ORG_NAME
  ADMIN_CERT=$CA_PATH/users/$ADMIN_CN/msp/signcerts/$ADMIN_CN-cert.pem
  cp $ADMIN_CERT $NODE_PATH/msp/admincerts
  check_error
}

#Copies the Admin user cert to the CA's msp/admincerts directory
#and to the Admin users msp/admincerts directory
copy_admin_cert_ca() {
  ORG_DIR=$1
  ORG_NAME=$2
  CA_PATH=$CRYPTO_CONFIG/$ORG_DIR/$ORG_NAME
  ADMIN_CN=Admin@$ORG_NAME
  ADMIN_CERT=$CA_PATH/users/$ADMIN_CN/msp/signcerts/$ADMIN_CN-cert.pem
  cp $ADMIN_CERT $CA_PATH/msp/admincerts
  check_error
  cp $ADMIN_CERT $CA_PATH/users/$ADMIN_CN/msp/admincerts
  check_error
}

for org in 1 2; do

  genmsp peerOrganizations org${org}.example.com users Admin@

  for peer in 0 1; do
    copy_admin_cert_node peerOrganizations org${org}.example.com peers peer${peer}
  done

  copy_admin_cert_ca peerOrganizations org${org}.example.com

done

genmsp ordererOrganizations example.com users Admin@
copy_admin_cert_node ordererOrganizations example.com orderers orderer
copy_admin_cert_ca ordererOrganizations example.com

configtxgen -profile TwoOrgsOrdererGenesis_v13 -outputBlock orderer.block


