#define _GNU_SOURCE

#include "psk_api.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "edhoc.h"
#include "edhoc/runtime_context.h"

#include "common/oscore_edhoc_error.h"

const char *RESP_PSK_FILE = "../../../test_vectors/psks_r.txt";
bool FROM_FILE = false;

void bytes_to_hex(char *hex_str, const uint8_t *in_data, uint32_t in_len)
{
	if (NULL != in_data) {
		for (uint32_t i = 0; i < in_len; i++) {
			sprintf(&hex_str[i * 2], "%02X ", in_data[i]);
		}
	}
}

/* Converts a single hex character to a byte */
static uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10); // Just in case (uppercase)
    return 0; // Handle invalid input safely
}

/* Converts a hex string to a binary byte array */
void hex_to_bytes(uint8_t *bytes, const char *hex_str, uint32_t len) {
    for (uint32_t i = 0; i < len / 2; i++) {
        bytes[i] = (hex_char_to_byte(hex_str[i * 2]) << 4) | hex_char_to_byte(hex_str[i * 2 + 1]);
    }
}

//"../../../test_vectors/psks_i.txt"
//"../../../test_vectors/psks_r.txt"
enum err store_creds(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r, const char *filename) {
    FILE *file = fopen(filename, "ab");
    if (!file) {
        perror("Error opening file");
        return unexpected_result_from_ext_lib;
    }

    // Allocate memory for hexadecimal representations
    char id_hex[id_cred_psk->len * 2 + 1]; // Each byte becomes 2 hex chars + null terminator
    char cred_i_hex[cred_i->len * 2 + 1];
    char cred_r_hex[cred_r->len * 2 + 1];
    
    // Convert binary to hex strings
    bytes_to_hex(id_hex, id_cred_psk->ptr, id_cred_psk->len);
    bytes_to_hex(cred_i_hex, cred_i->ptr, cred_i->len);
    bytes_to_hex(cred_r_hex, cred_r->ptr, cred_r->len);

    // Null-terminate the strings
    id_hex[id_cred_psk->len * 2] = '\0';
    cred_i_hex[cred_i->len * 2] = '\0';
    cred_r_hex[cred_r->len * 2] = '\0';

    // Write to file in "id_cred_psk":"cred_i"/"cred_r", format
    fprintf(file, "\"%s\":\"%s\"/\"%s\",\n", id_hex, cred_i_hex, cred_r_hex);

    fclose(file);
    return ok;
}

/* Function to get the last line of a file */
char *get_last_line(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    char *last_line = NULL;
    size_t len = 0;
    ssize_t read;
    char *temp = NULL;

    while ((read = getline(&temp, &len, file)) != -1) {
        free(last_line);
        last_line = strdup(temp); // Store the last read line
    }

    free(temp);
    fclose(file);
    return last_line;
}

/* Function to parse the last line and extract id_cred_psk and cred_psk */
enum err get_last_creds(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r, const char *filename) {
    char *last_line = get_last_line(filename);
    if (!last_line) {
        return unexpected_result_from_ext_lib; // Failed to read the last line
    }

    // Find the first and second quotes
    char *first_quote = strchr(last_line, '"');
    if (!first_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }
    
    char *second_quote = strchr(first_quote + 1, '"');
    if (!second_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }
    
    char *third_quote = strchr(second_quote + 1, '"');
    if (!third_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }
    
    char *fourth_quote = strchr(third_quote + 1, '"');
    if (!fourth_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }

    char *fifth_quote = strchr(fourth_quote + 1, '"');
    if (!fifth_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }
    
    char *sixth_quote = strchr(fifth_quote + 1, '"');
    if (!sixth_quote) {
        free(last_line);
        return unexpected_result_from_ext_lib;
    }

    uint32_t id_len = (uint32_t)(second_quote - first_quote - 1);
    uint32_t cred_i_len = (uint32_t)(fourth_quote - third_quote - 1);
    uint32_t cred_r_len = (uint32_t)(sixth_quote - fifth_quote - 1);

    id_cred_psk->len = (uint32_t)(id_len / 2);
    cred_i->len = (uint32_t)(cred_i_len / 2);
    cred_r->len = (uint32_t)(cred_r_len / 2);

    // Convert hex to binary
    hex_to_bytes(id_cred_psk->ptr, first_quote + 1, id_len);
    hex_to_bytes(cred_i->ptr, third_quote + 1, cred_i_len);
    hex_to_bytes(cred_r->ptr, fifth_quote + 1, cred_r_len);

    free(last_line);
    return ok;
}

/*Function to change the route to the Responder's PSK file*/
    //Relative route to the Responder PSKs file.
    // Select "../../../test_vectors/psks_r.txt" when executing from samples.
    // Select "../uoscore-uedhoc/test_vectors/psks_r.txt" when executing from FreeRADIUS.
    // Select "../../uoscore-uedhoc/test_vectors/psks_r.txt" when executing from WPA_Supplicant.
enum err set_resp_creds_file(char *filename) {
    RESP_PSK_FILE = filename;
    FROM_FILE = true;
    return ok;
}

/* Function to retrieve cred_psk given an id_cred_psk */
enum err get_creds_by_id(struct byte_array *id_cred_psk, struct byte_array *cred_i, struct byte_array *cred_r) {

    if (!FROM_FILE){
        return not_implemented;
    }

    FILE *file = fopen(RESP_PSK_FILE, "r");
    if (!file) {
        perror("Error opening file");
        return unexpected_result_from_ext_lib;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    // Convert id_cred_psk to hex string for comparison
    char id_hex[(id_cred_psk->len * 2) + 1];
    bytes_to_hex(id_hex, id_cred_psk->ptr, id_cred_psk->len);

    while ((read = getline(&line, &len, file)) != -1) {

        char *first_quote = strchr(line, '"');
        if (!first_quote) continue;

        char *second_quote = strchr(first_quote + 1, '"');
        if (!second_quote) continue;

        char *third_quote = strchr(second_quote + 1, '"');
        if (!third_quote) continue;

        char *fourth_quote = strchr(third_quote + 1, '"');
        if (!fourth_quote) continue;

        char *fifth_quote = strchr(fourth_quote + 1, '"');
        if (!fifth_quote) continue;

        char *sixth_quote = strchr(fifth_quote + 1, '"');
        if (!sixth_quote) continue;

        printf("%s\n", "Quotes extracted.");
        
        // Extract id_cred_psk from the current line
        uint32_t id_len = (uint32_t)(second_quote - first_quote - 1);
        if (id_len != id_cred_psk->len * 2) continue;

        if (strncmp(first_quote + 1, id_hex, id_len) == 0) {
            // Found matching id_cred_psk, now extract creds
            uint32_t cred_i_len = (uint32_t)(fourth_quote - third_quote - 1);
            uint32_t cred_r_len = (uint32_t)(sixth_quote - fifth_quote - 1);
 
            cred_i->len = (uint32_t)(cred_i_len / 2);
            cred_r->len = (uint32_t)(cred_r_len / 2);

            // Convert hex to binary
            hex_to_bytes(cred_i->ptr, third_quote + 1, cred_i_len);
            hex_to_bytes(cred_r->ptr, fifth_quote + 1, cred_r_len);

            fclose(file);
            free(line);
            return ok;
        }
    }

    fclose(file);
    free(line);
    return credential_not_found; // id_cred_psk not found
    
}
