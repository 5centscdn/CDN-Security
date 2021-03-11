/*
 * ARCHFLAGS='-arch i386' gcc akamai_token_v2.c -o akamai_token_v2 -lcrypto -lssl -lcurl
 *
 * Copyright (c) 2012, Akamai Technologies, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Akamai Technologies nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>

#define MAX_FIELD_LEN 512
#define MAX_HASH_SOURCE 102400
#define MAX_TOKEN_LEN 102400

void displayHelp()
{
    printf("Usage:akamai_token_v2 [options]\n");
    printf("   -t, --token_type TOKEN_TYPE      Select a preset: (Not Supported Yet)\n");
    printf("                                        2.0\n");
    printf("                                        2.0.2\n");
    printf("                                        PV\n");
    printf("                                        Debug\n");
    printf("   -n, --token_name TOKEN_NAME      Parameter name for the new token. [Default:hdnts]\n");
    printf("   -i, --ip IP_ADDRESS              IP Address to restrict this token to.\n");
    printf("   -s, --start_time START_TIME      What is the start time. (use now for the current time)\n");
    printf("   -e, --end_time END_TIME          When does this token expire? --end_time overrides --window\n");
    printf("   -w, --window WINDOW_SECONDS      How long is this token valid for?\n");
    printf("   -u, --url URL                    URL path.\n");
    printf("   -a, --acl ACCESS_LIST            Access control list delimted by ! [ie. /*]\n");
    printf("   -k, --key KEY                    Secret required to generate the token.\n");
    printf("   -p, --payload PAYLOAD            Additional text added to the calculated digest.\n");
    printf("   -A, --algo ALGORITHM             Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]\n");
    printf("   -S, --salt SALT                  Additional data validated by the token but NOT included in the token body.\n");
    printf("   -I, --session_id SESSION_ID      The session identifier for single use tokens or other advanced cases.\n");
    printf("   -d, --field_delimiter            Character used to delimit token body fields. [Default:~]\n");
    printf("   -D, --acl_delimiter              Character used to delimit acl fields. [Default:!]\n");
    printf("   -x, --escape_early               Causes strings to be url encoded before being used. (legacy 2.0 behavior)\n");
    printf("   -X, --escape_early_upper         Causes strings to be url encoded before being used. (legacy 2.0 behavior)\n");
    printf("   -v, --verbose                    Display more details about the inputs\n");
    printf("   -h, --help                       Display this help info\n");
}

typedef struct AkamaiTokenConfig
{
    unsigned char token_type[MAX_FIELD_LEN];
    unsigned char token_name[MAX_FIELD_LEN];
    unsigned char ip[MAX_FIELD_LEN];
    int has_start_time;
    time_t start_time;
    time_t end_time;
    time_t window_seconds;
    unsigned char url[MAX_FIELD_LEN];
    unsigned char acl[MAX_FIELD_LEN];
    unsigned char key[MAX_FIELD_LEN];
    unsigned char payload[MAX_FIELD_LEN];
    unsigned char algo[MAX_FIELD_LEN];
    unsigned char salt[MAX_FIELD_LEN];
    unsigned char session_id[MAX_FIELD_LEN];
    char field_delimiter;
    char acl_delimiter;
    int escape_early;
    int escape_early_upper;
    int verbose;
} akamai_token_config_t;

void initializeAkamaiTokenConfig(akamai_token_config_t *config)
{
    // Set default values for each configuration parameter.
    strcpy(config->token_type, "");
    strcpy(config->token_name, "hdnts");
    strcpy(config->ip, "");
    config->has_start_time = 0;
    config->start_time = 0;
    config->end_time = 0;
    config->window_seconds = 0;
    strcpy(config->url, "");
    strcpy(config->acl, "");
    strcpy(config->key, "");
    strcpy(config->payload, "");
    strcpy(config->algo, "sha256");
    strcpy(config->salt, "");
    strcpy(config->session_id, "");
    config->field_delimiter = '~';
    config->acl_delimiter = '!';
    config->escape_early = 0;
    config->escape_early_upper = 0;
    config->verbose = 0;
}

void strToUpper(char * str)
{
    int i = 0;
    for (; i < strlen(str) ; i++)
        str[i] = toupper(str[i]);
}

void strToLower(char * str)
{
    int i = 0;
    for (; i < strlen(str) ; i++)
        str[i] = tolower(str[i]);
}

size_t hexToBin(unsigned char *dest, size_t dest_len, const unsigned char *src, size_t src_len)
{
    if (src_len % 2)
    {
        printf("You must have an even number of characters to convert from hex to binary.\n");
        exit(1);
    }
    if (dest_len < (src_len / 2))
    {
        printf("Destination buffer is not large enough to hold binary data.\n");
        exit(1);
    }
    int i = 0;
    for( ; i < src_len ; i += 2)
    {
        char b1 = toupper(src[i]) - '0';
        char b2 = toupper(src[i+1]) - '0';
        if (b1 > 9)
            b1 -= 7; // Adjust the value from A-F to 10-15
        if (b2 > 9)
            b2 -= 7; // Adjust the value from A-F to 10-15
        dest[i/2] = (b1<<4) + b2;
    }
    return (size_t)(src_len/2);
}

size_t binToHex(unsigned char *dest, size_t dest_len, const unsigned char *src, size_t src_len, int to_lower)
{
    if (dest_len < ((src_len * 2)+1))
    {
        printf("Destination buffer is not large enough to hold hex encoded source string.\n");
        exit(1);
    }
    int i = 0;
    for( ; i < src_len ; i++)
    {
        char b1 = (src[i] >> 4) + '0';
        char b2 = (src[i] & 0x0f) + '0';
        if (b1 > '9')
            b1 += 7; // Offset to A-F for values greater than 9.
        if (b2 > '9')
            b2 += 7; // Offset to A-F for values greater than 9.
        dest[(i*2)] = to_lower ? tolower(b1) : b1;
        dest[(i*2)+1] = to_lower ? tolower(b2) : b2;
    }
    dest[(src_len*2)+1] = '\0';
    return (size_t)(src_len * 2);
}

char * escapeEarly(akamai_token_config_t *config, char *dest, size_t dest_len, char *src)
{
    if (!config->escape_early && !config->escape_early_upper)
    {
        if (dest_len > strlen(src))
            strcpy(dest, src);
        else
            printf("Unable to escape '%s'\n", src);
        return dest;
    }

    size_t src_len = strlen(src);
    CURL *handle = curl_easy_init();
    char *encoded_url = curl_easy_escape(handle, src, strlen(src));
    if (encoded_url)
    {
        int i = 0;
        for (; i < strlen(encoded_url) ;)
        {
            if (encoded_url[i] == '%')
            {
                if (config->escape_early_upper)
                {
                    encoded_url[i+1] = toupper(encoded_url[i+1]);
                    encoded_url[i+2] = toupper(encoded_url[i+2]);
                    i += 3;
                }
                else if (config->escape_early)
                {
                    encoded_url[i+1] = tolower(encoded_url[i+1]);
                    encoded_url[i+2] = tolower(encoded_url[i+2]);
                    i += 3;
                }
            }
            else
                i++;
        }
        if (config->verbose)
            printf("new url %s\n", encoded_url);
        if (strlen(encoded_url) < dest_len)
            strcpy(dest, encoded_url);
        else
        {
            printf("Unable to escape '%s' early", src);
            strcpy(dest, src);
        }
        curl_free(encoded_url);
    }
    else
    {
        printf("Unable to escape '%s' early", src);
        strcpy(dest, src);
    }
    curl_easy_cleanup(handle);
    return dest;
}

time_t getUTCNow(void)
{
    // Manually calculate the offset for UTC based on the difference between UTC
    // and local time.
    time_t now = time(NULL);
    struct tm utc_tm = *gmtime(&now);
    struct tm local_tm = *localtime(&now);
    int offset_hours = local_tm.tm_hour - utc_tm.tm_hour;
    utc_tm.tm_hour += offset_hours;
    return mktime(&utc_tm);
}

void generateAkamaiToken(akamai_token_config_t *config)
{
    if (strlen(config->token_name) <= 0)
    {
        printf("You must define a token name.\n");
        exit(1);
    }
    if (config->end_time <= 0)
    {
        if (config->window_seconds > 0)
        {
            if (config->has_start_time == 0)
            {
                // If we have a duration window without a start time,
                // calculate the end time starting from the current time.
                time_t now = time(NULL);
                config->end_time = getUTCNow() + config->window_seconds;
            } else {
                config->end_time = config->start_time + config->window_seconds;
            }
        } else {
            printf("You must provide an expiration time or a duration window.\n");
            exit(1);
        }
    }
    if (strlen(config->key) <= 0)
    {
        printf("You must provide a secret in order to generate a new token.\n");
        exit(1);
    }
    if ((strlen(config->url) <= 0) && (strlen(config->acl) <= 0))
    {
        printf("You must provide a URL or an ACL.\n");
        exit(1);
    }
    else if ((strlen(config->url) > 0) && (strlen(config->acl) > 0))
    {
        printf("You must provide a URL OR an ACL, not both.\n");
        exit(1);
    }
  
    if (config->verbose)
    {
        printf("Akamai Token Generation Parameters\n");
        printf("Token Type      : %s\n", config->token_type);
        printf("Token Name      : %s\n", config->token_name);
        printf("Start Time      : %d\n", (int)config->start_time);
        printf("Window(seconds) : %d\n", (int)config->window_seconds);
        printf("End Time        : %d\n", (int)config->end_time);
        printf("IP              : %s\n", config->ip);
        printf("URL             : %s\n", config->url);
        printf("ACL             : %s\n", config->acl);
        printf("Key/Secret      : %s\n", config->key);
        printf("Payload         : %s\n", config->payload);
        printf("Algo            : %s\n", config->algo);
        printf("Salt            : %s\n", config->salt);
        printf("Session ID      : %s\n", config->session_id);
        printf("Field Delimiter : %c\n", config->field_delimiter);
        printf("ACL Delimiter   : %c\n", config->acl_delimiter);
        printf("Escape Early    : %s\n", config->escape_early ? "Yes" : "No");
        printf("Generating token...\n");
    }
    if (config->end_time < config->start_time)
        printf("WARNING:Token will have already expired.\n");
  
    unsigned char hash_source[MAX_HASH_SOURCE];
    size_t hash_source_len = 0;
    memset(hash_source, '\0', sizeof(hash_source));
    unsigned char new_token[MAX_TOKEN_LEN];
    memset(new_token, '\0', sizeof(new_token));
    size_t new_token_len = 0;
    char encoded_field[MAX_FIELD_LEN];
    size_t encoded_size = sizeof(encoded_field);

    size_t ip_len = strlen(config->ip);
    if (ip_len > 0)
    {
        sprintf(&new_token[new_token_len], "ip=%s%c",
                escapeEarly(config, encoded_field, encoded_size, config->ip), config->field_delimiter);
        new_token_len = strlen(new_token);
    }
    if (config->has_start_time != 0)
    {
        sprintf(&new_token[new_token_len], "st=%d%c", (int)config->start_time, config->field_delimiter);
        new_token_len = strlen(new_token);
    }
    sprintf(&new_token[new_token_len], "exp=%d%c", (int)config->end_time, config->field_delimiter);
    new_token_len = strlen(new_token);
    if (strlen(config->acl) > 0)
    {
        sprintf(&new_token[new_token_len], "acl=%s%c",
                escapeEarly(config, encoded_field, encoded_size, config->acl), config->field_delimiter);
        new_token_len = strlen(new_token);
    }
    if (strlen(config->session_id) > 0)
    {
        sprintf(&new_token[new_token_len], "id=%s%c",
                escapeEarly(config, encoded_field, encoded_size, config->session_id), config->field_delimiter);
        new_token_len = strlen(new_token);
    }
    if (strlen(config->payload) > 0)
    {
        sprintf(&new_token[new_token_len], "data=%s%c",
                escapeEarly(config, encoded_field, encoded_size, config->payload), config->field_delimiter);
        new_token_len = strlen(new_token);
    }
    sprintf(&hash_source[hash_source_len], "%s", new_token);
    hash_source_len = strlen(hash_source);
    if ((strlen(config->url) > 0) && (strlen(config->acl) <= 0))
    {
        sprintf(&hash_source[hash_source_len], "url=%s%c",
                escapeEarly(config, encoded_field, encoded_size, config->url), config->field_delimiter);
        hash_source_len = strlen(hash_source);
    }
    if (strlen(config->salt) > 0)
    {
        sprintf(&hash_source[hash_source_len], "salt=%s%c", config->salt, config->field_delimiter);
        hash_source_len = strlen(hash_source);
    }

    // Prepare the key.
    char bin_key[MAX_FIELD_LEN];
    size_t bin_key_len = hexToBin(bin_key, (size_t)MAX_FIELD_LEN, config->key, strlen(config->key));

    // Generate the hash.
    HMAC_CTX ctx;
    unsigned char result[MAX_FIELD_LEN];
    unsigned int result_len = 32;
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    HMAC_CTX_init(&ctx);

    // Set the appropriate algorithm.
    EVP_MD *algo = (EVP_MD *)EVP_sha256();
    if (strcasecmp(config->algo, "sha1") == 0)
        algo = (EVP_MD *)EVP_sha1();
    else if (strcasecmp(config->algo, "md5") == 0)
        algo = (EVP_MD *)EVP_md5();

    HMAC_Init_ex(&ctx, bin_key, bin_key_len, algo, NULL);
    HMAC_Update(&ctx, hash_source, hash_source_len-1);
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);
    unsigned char hex_hmac[MAX_FIELD_LEN];
    size_t hex_hmac_len = binToHex(hex_hmac, MAX_FIELD_LEN, result, result_len, 1);
    sprintf(&new_token[new_token_len], "hmac=%s", hex_hmac);

    printf("%s=%s\n", config->token_name, new_token);
}

int main(int argc, char *argv[])
{
    akamai_token_config_t config;
    initializeAkamaiTokenConfig(&config);

    int c;
    int option_index = 0;

    while (1)
    {
        static struct option long_options[] =
        {
            // {name, hash_arg, flag, val}
            {"token_type", required_argument, 0, 't'},
            {"token_name", required_argument, 0, 'n'},
            {"ip", required_argument, 0, 'i'},
            {"start_time", required_argument, 0, 's'},
            {"end_time", required_argument, 0, 'e'},
            {"window", required_argument, 0, 'w'},
            {"url", required_argument, 0, 'u'},
            {"acl", required_argument, 0, 'a'},
            {"key", required_argument, 0, 'k'},
            {"payload", required_argument, 0, 'p'},
            {"algo", required_argument, 0, 'A'},
            {"salt", required_argument, 0, 'S'},
            {"session_id", required_argument, 0, 'I'},
            {"field_delimiter", required_argument, 0, 'd'},
            {"acl_delimiter", required_argument, 0, 'D'},
            {"escape_early", no_argument, 0, 'X'},
            {"verbose", no_argument, 0, 'v'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        c = getopt_long(argc, argv, "t:n:i:s:e:w:u:a:k:p:A:S:I:d:D:xXvh",
                        long_options, &option_index);
        if (c == -1)
        {
            // No more options.
            break;
        }

        switch(c)
        {
            case 0:
                if (long_options[option_index].flag != 0)
                    // This option is a flag with an address of a variable so
                    // there is nothing else to do.
                    break;
                break;
            case 't':
                if (strlen(optarg) < MAX_FIELD_LEN)
                {
                    strcpy(config.token_type, optarg);
                    strToUpper(config.token_type);
                }
                break;
            case 'n':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.token_name, optarg);
                break;
            case 'i':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.ip, optarg);
                break;
            case 's':
                if (strlen(optarg) > 0)
                {
                    config.has_start_time = 1;
                    if (strcasecmp(optarg, "NOW") == 0)
                    {
                        // Initialize the start time to the current time.
                        time_t now = time(NULL);
                        config.start_time = getUTCNow();
                    }
                    else
                        sscanf(optarg, "%d", (int *)&config.start_time);
                }
                break;
            case 'e':
                if (strlen(optarg) > 0)
                {
                    if (strcasecmp(optarg, "NOW") == 0)
                    {
                        // Initialize the start time to the current time.
                        time_t now = time(NULL);
                        config.end_time = getUTCNow();
                    }
                    else
                        sscanf(optarg, "%d", (int *)&config.end_time);
                }
                break;
            case 'w':
                sscanf(optarg, "%d", (int *)&config.window_seconds);
                break;
            case 'u':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.url, optarg);
                break;
            case 'a':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.acl, optarg);
                break;
            case 'k':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.key, optarg);
                break;
            case 'p':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.payload, optarg);
                break;
            case 'A':
                if (strlen(optarg) < MAX_FIELD_LEN)
                {
                    if (strcasecmp(optarg, "SHA1") == 0 ||
                        strcasecmp(optarg, "SHA256") == 0 ||
                        strcasecmp(optarg, "MD5") == 0)
                    {
                        strcpy(config.algo, optarg);
                    }
                    else
                    {
                        printf("algo must be one of sha1, sha256, or md5\n");
                        exit(1);
                    }
                }
                break;
            case 'S':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.salt, optarg);
                break;
            case 'I':
                if (strlen(optarg) < MAX_FIELD_LEN)
                    strcpy(config.session_id, optarg);
                break;
            case 'd':
                if (strlen(optarg) >= 1)
                    config.field_delimiter = optarg[0];
                break;
            case 'D':
                if (strlen(optarg) >= 1)
                    config.acl_delimiter = optarg[0];
                break;
            case 'x':
                config.escape_early = 1;
                break;
            case 'X':
                config.escape_early_upper = 1;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                displayHelp();
                exit(0);
                break;
            case '?':
                if (optopt == 't')
                {
                  printf("token_type must be either URL or COOKIE\n");
                  exit(1);
                }
                else if (optopt == 'n')
                {
                    strcpy(config.token_name, "hdnts");
                }
                else if (optopt == 'A')
                {
                    strcpy(config.algo, "sha256");
                }
                break;
        } // switch
    } // while

    generateAkamaiToken(&config);

  return 0;
}
