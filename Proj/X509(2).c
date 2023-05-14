#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"



void Sanitise(char *str) {
    
    char *src = str, *dst = str;
    
    while (*src != '\0') {
        if (*src == ' ' || *src == '\n' || *src == '=') {
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}


EVP_PKEY* generate_key() {
  /* EVP_PKEY structure is for storing an algorithm-independent private key in memory. */
  EVP_PKEY* pkey = EVP_PKEY_new();

  /* Generate a RSA key and assign it to pkey.
   * RSA_generate_key is deprecated.
   */
  BIGNUM* bne = BN_new();
  BN_set_word(bne, RSA_F4);
  RSA* rsa = RSA_new();
  RSA_generate_key_ex(rsa, 2048, bne, NULL);

  EVP_PKEY_assign_RSA(pkey, rsa);

  return pkey;
}

X509* generate_x509 (EVP_PKEY* pkey, char * validity_period , char * name , char * issuer, int SN, 
 char* org, char* org_unit, char* locality, char* state, char* country) {
  X509* x509 = X509_new();

  /* set a few parameters of the certificate. */

  /* certificate expiration date: 365 days from now (60s * 60m * 24h * 365d) */
  int days = atoi(validity_period);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 60 * 60); // zile * ore * minute * secunde

  X509_set_pubkey(x509, pkey);


//   X509_set_issuer_name(x509, issuer);

  

    // // Setarea versiunii certificatului la v3

     X509_set_version(x509, 3);

     // Setarea numărului serial unic pentru certificat
     ASN1_INTEGER_set(X509_get_serialNumber(x509), SN);

    X509_NAME *name_obj = X509_NAME_new();

    //Adding organization name
    if (org != NULL) {
        X509_NAME_add_entry_by_txt(name_obj, "C", MBSTRING_ASC, (unsigned char*)country, -1, -1, 0);
    }

    // Adding organizational unit name
    if (org_unit != NULL) {
        X509_NAME_add_entry_by_txt(name_obj, "ST", MBSTRING_ASC, (unsigned char*)state, -1, -1, 0);
    }

    // Adding locality name
    if (locality != NULL) {
        X509_NAME_add_entry_by_txt(name_obj, "L", MBSTRING_ASC, (unsigned char*)locality, -1, -1, 0);
    }

    // Adding state name
    if (state != NULL) {
        X509_NAME_add_entry_by_txt(name_obj, "O", MBSTRING_ASC, (unsigned char*)org, -1, -1, 0);
    }

    // Adding country name
    if (country != NULL) {
        X509_NAME_add_entry_by_txt(name_obj, "OU", MBSTRING_ASC, (unsigned char*)org_unit, -1, -1, 0);
    }

     // Setarea numelui emițătorului (issuer) și al subiectului
   
    
    X509_NAME_add_entry_by_txt(name_obj, "CN", MBSTRING_ASC, (unsigned char*)issuer, -1, -1, 0);
    X509_set_issuer_name(x509, name_obj);
    X509_NAME_free(name_obj);

    name_obj = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name_obj, "CN", MBSTRING_ASC, (unsigned char*)name, -1, -1, 0);
    X509_set_subject_name(x509, name_obj);
    X509_NAME_free(name_obj);


  /* finally sign the certificate with the key. */
  X509_sign(x509, pkey, EVP_sha256());
 // free(name_obj);
  return x509;
}


bool check_certificate_valid(X509* x509) {
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  X509_STORE* store = X509_STORE_new();

  X509_STORE_add_cert(store, x509);
  X509_STORE_CTX_init(ctx, store, x509, NULL);

  return X509_verify_cert(ctx) == 1? true : false;
}



X509_CRL* create_crl() {
  X509_CRL* crl = X509_CRL_new();
  return crl;
}

void Revoc_cert(X509_CRL* crl, X509* cert, EVP_PKEY* issuer_key, int serial, char* reason) {
  X509_REVOKED* revoked = X509_REVOKED_new();
  ASN1_INTEGER_set((ASN1_INTEGER *) X509_REVOKED_get0_serialNumber(revoked), serial);
  X509_gmtime_adj((ASN1_TIME*) X509_REVOKED_get0_revocationDate(revoked), 0);
  X509_REVOKED_set_revocationDate(revoked,(ASN1_TIME*) X509_REVOKED_get0_revocationDate(revoked));
  X509_CRL_add0_revoked(crl, revoked);
  X509_CRL_sort(crl);
  X509_CRL_sign(crl, issuer_key, EVP_sha256());
}


X509* Extend_CERT (EVP_PKEY* pkey, char * validity_period , char * name , char * issuer, int SN, 
 char* org, char* org_unit, char* locality, char* state, char* country, char* cert_path, char* key_path) {
  
  X509* x509 = X509_new();

  /* load existing certificate and key */
  FILE* cert_file = fopen(cert_path, "rb");
  X509* existing_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
  fclose(cert_file);

  FILE* key_file = fopen(key_path, "rb");
  EVP_PKEY* existing_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
  fclose(key_file);

  /* set a few parameters of the certificate. */
  int days = atoi(validity_period);



  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 60 * 60);

  /* copy the existing certificate and modify the expiration date */
  X509_set_version(x509, X509_get_version(existing_cert));
  X509_set_pubkey(x509, X509_get_pubkey(existing_cert));
  X509_set_subject_name(x509, X509_get_subject_name(existing_cert));
  X509_set_issuer_name(x509, X509_get_issuer_name(existing_cert));
  ASN1_INTEGER_set(X509_get_serialNumber(x509), SN);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 60 * 60);

  /* sign the certificate with the existing private key */
  X509_sign(x509, pkey, EVP_sha256());

  EVP_PKEY_free(existing_key);
  X509_free(existing_cert);

  return x509;
}


int main(int argc, char *argv[]) {
    X509 *root_cert;
    RSA *root_key;
    FILE *fp;
    int option_index = 0, c;
    //EVP_PKEY *pkey = EVP_PKEY_new();


 // Private Key

  EVP_PKEY* pkey = generate_key();
  FILE* pkey_file = fopen("rootca.key", "wb");
  PEM_write_PrivateKey(pkey_file, pkey, NULL,NULL ,0 ,NULL ,NULL);
  fclose(pkey_file);

  EVP_PKEY_free(pkey);

    // Argumentele de linie de comandă
    char *root_cert_file = NULL;
    char *validity_period = NULL;
    char *name = NULL;
    char *issuer_name = NULL;
    int  SN = 0;
    char * sn = NULL;
    char *organization = NULL;
    char *organizational_unit = NULL;
    char *locality = NULL;
    char *state = NULL;
    char *country = NULL;

    // Definirea opțiunilor de linie de comandă
    static struct option long_options[] = {
        {"root-cert", required_argument, 0, 'r'},
        {"validity-period", required_argument, 0, 'v'},
        {"name", required_argument, 0, 'n'},
        {"issuer-name", required_argument, 0, 'i'},
        {"serial-number", required_argument, 0 , 's' },
        {"organization", required_argument, 0, 'o'},
        {"organizational-unit", required_argument, 0, 'u'},
        {"locality", required_argument, 0, 'l'},
        {"state", required_argument, 0, 't'},
        {"country", required_argument, 0, 'y'},
        {0, 0, 0, 0}
    };
    

    // Parsarea argumentelor de linie de comandă
    while ((c = getopt_long(argc, argv, "r:v:n:i:s:o:u:l:t:y:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                root_cert_file = optarg;
                Sanitise(root_cert_file);
                break;
            case 'v':
                validity_period = optarg;
                Sanitise(validity_period);
                break;
            case 'n':
                name = optarg;
                Sanitise(name);
                break;
            case 'i':
                issuer_name = optarg;
                Sanitise(issuer_name);
                break;
            case 's':
                sn = optarg;
                Sanitise(sn);
                SN = atoi(sn);
                break;
            case 'o':
                organization = optarg;
                Sanitise(organization);
                break;
            case 'u':
                organizational_unit = optarg;
                Sanitise(organizational_unit);
                break;
            case 'l':
                locality = optarg;
                Sanitise(locality);
                break;
            case 't':
                state = optarg;
                Sanitise(state);
                break;
            case 'y':
                country = optarg;
                Sanitise(country);
                break;
            default:
                printf("Usage: %s --root-cert=<file> --validity-period=<days> --name=<name> \
                --issuer-name=<issuer> --serial-number=<long> [--organization=<organization>] \
                [--organizational-unit=<unit>] [--locality=<locality>]    [--state=<state>] [--country=<country>]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Verificarea argumentelor de linie de comandă
   if (!root_cert_file || !validity_period || !name || !issuer_name || SN == 0 || 
       !organization || !organizational_unit || !locality || !state || !country) {
         printf("Usage: %s --root-cert=<file> --validity-period=<days> --name=<name> --issuer-name=<issuer>\n\
                --serial-number=<long> [--organization=<organization>] [--organizational-unit=<unit>] [--locality=<locality>]\n\
                [--state=<state>] [--country=<country>]\n", argv[0]);

                printf("root_cert_file = %s , validity_period = %s , name = %s , issuer_name = %s , serial-number = %d \n \
                        organization = %s , organizational_unit = %s , locality = %s , state = %s , country = %s \n "
                , root_cert_file 
                , validity_period 
                , name 
                , issuer_name 
                , SN 
                , organization 
                , organizational_unit 
                , locality 
                , state 
                ,country);
                exit(EXIT_FAILURE);
    }



    EVP_PKEY* pkeyPair = generate_key();
    X509* x509 = generate_x509(pkeyPair,validity_period,name,issuer_name,SN,
     organization , organizational_unit ,locality ,state , country);
    
    FILE* x509_file = fopen("rootca.crt", "wb");
    PEM_write_X509(x509_file, x509);
    fclose(x509_file);

    if ( check_certificate_valid(x509)) {
     printf("cert is valid");}
    else {
     printf("cert is NOT valid");
    }


     // Create a new CRL
    X509_CRL* crl = create_crl();

    // Add a revoked certificate to the CRL
    X509* cert = x509; // get the certificate to be revoked
    EVP_PKEY* issuer_key = pkey; // get the issuer's private key
    int serial = SN; // get the serial number of the certificate to be revoked
    char* reason = "Non Compliance"; // specify the reason for revocation
    Revoc_cert(crl, cert, issuer_key, serial, reason);



    // Extend the certificate 

    X509 * NewCert =  Extend_CERT(pkey,"10",name,issuer_name,1231231,"pp",organizational_unit,"WWW","ASD","AAAA","rootca.crt","rootca.key");
    
    FILE* x509_file2 = fopen("new_rootca.crt", "wb");
    PEM_write_X509(x509_file2, NewCert);
    fclose(x509_file2);

    // free(root_cert_file);
    // free(validity_period);
    // free(name);
    // free(issuer_name);
    // free(organization);
    // free(organizational_unit);
    // free(locality);
    // free(state);
    // free(country);
    // free(sn);

    return 0;
}
