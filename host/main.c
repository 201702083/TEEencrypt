/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_LEN 1024
#define RSA_PLAIN_LEN 86 // 1024/8 - 42 (padding)
#define RSA_CIPHER_LEN (RSA_KEY_LEN/8)

#define CEASER_PLAIN_LEN 64 

void write_file(char *name, char *text, int key) {
	FILE *f = fopen(name, "w+");
	fwrite(text, strlen(text), 1, f);
	if (key != 0){
		fprintf(f, "%d", key);
	}
	fclose(f);	
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t err_origin;
	// base set

	char plaintext[CEASER_PLAIN_LEN];
	char ciphertext[CEASER_PLAIN_LEN];
	char ceaser_key[CEASER_PLAIN_LEN];
	// ~ ceaser encryption

	char plain[RSA_PLAIN_LEN];
	char cipher[RSA_CIPHER_LEN];
	// ~ RSA encryption

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	memset(&op, 0, sizeof(op));
	// init 

	// TEEencrypt argv[1] argv[2] Ceaser
	if (!strcmp(argv[3], "Ceaser")){
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						TEEC_NONE, TEEC_NONE);
		
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = CEASER_PLAIN_LEN;
		op.params[1].value.a = 0;

		// TEEencrypt -e @input Ceaser
		// 	@input  : textfile
		// 	@output : ceaserCipher.txt
		//				- encrypted text + \n + encrypt key
		if (!strcmp(argv[1], "-e")){
			printf("Ceaser encryption\n");
			// Read file to encrypt	
			FILE *pf = fopen(argv[2], "r");
			if (pf == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;	
			}
			fgets(plaintext, sizeof(plaintext), pf);
			fclose(pf);
			// Copy plaintext to op's share memory
			memcpy(op.params[0].tmpref.buffer, plaintext, CEASER_PLAIN_LEN); 
			
			// Invoke TA's ceaser encrypt service
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
					
			// Copy ta's return value to ciphertext
			memcpy(ciphertext, op.params[0].tmpref.buffer, CEASER_PLAIN_LEN);
			// Print result
			printf("Encrypted text : %s\n", ciphertext);
			printf("key : %d\n", op.params[1].value.a);
			// Write ciphertext&key to txt file
			write_file("ceaserCipher.txt", plaintext, op.params[1].value.a);
		} 
		// TEEencrypt -d @input Ceaser
		// 	@input  : ceaserCipher.txt
		// 	@output : ceaserPlain.txt
		//		ceaserPlain must be equal to original txt.
		else if (!strcmp(argv[1],"-d")){
			printf("Ceser decryption\n");
			// Read file to decrypt
			FILE *ef = fopen(argv[2], "r");
			if (ef == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;
			}
			fgets(ciphertext, sizeof(ciphertext), ef);
			fgets(ceaser_key, sizeof(ceaser_key), ef);
			// Get ciphertext & key
			fclose(ef);
			// Close file pointer

			// Copy ciphertext to op's share memory
			memcpy(op.params[0].tmpref.buffer, ciphertext, CEASER_PLAIN_LEN);
			int key = atoi(ceaser_key);
			op.params[1].value.a = key;

			// Invoke TA's ceaser decryption service
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
			
			// Copy ta's return value to ciphertext
			memcpy(plaintext, op.params[0].tmpref.buffer, CEASER_PLAIN_LEN);
			printf("Decrypted text : %s\n", plaintext);
			printf("Key : %d\n", op.params[1].value.a);
			write_file("ceaserPlain.txt", plaintext, 0);
		}else{ // Exception for invalid argument
			printf("Invalid argument %s\n", argv[2]);
			return 1;
		}
	// TEEencrypt argv[1] argv[2] RSA
	}else if (!strcmp(argv[3],"RSA")){		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
								TEEC_MEMREF_TEMP_OUTPUT,
								TEEC_NONE, TEEC_NONE);
	
		op.params[0].tmpref.buffer = plain;
		op.params[0].tmpref.size = RSA_PLAIN_LEN;
		op.params[1].tmpref.buffer = cipher;
		op.params[1].tmpref.size = RSA_CIPHER_LEN;
		// Invoke GEN RSA KEYS
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_GENKEYS, NULL, NULL);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
		printf("\n=========== Keys already generated. ==========\n");
		// TEEencrypt -e @input RSA
		// @input  : textfile
		// @output : rsaCipher.txt , rsaPlain.txt
		//        rsaPlain must be equal to texfile
		if (!strcmp(argv[1],"-e")){
			printf("RSA encryption\n");
			// Read file to encrypt	
			FILE *pf = fopen(argv[2], "r");
			if (pf == NULL){
				printf("%s : not found\n", argv[2]);
				return 1;	
			}
			fgets(plain, sizeof(plain), pf);
			fclose(pf);
			// enc
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_ENC_VALUE,
				 &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_ENC_VALUE) failed 0x%x origin 0x%x\n",
					res, err_origin);
			printf("\nThe hex sent was encrypted: %x\n", cipher);
			write_file("rsaCipher.txt", cipher, 0);
			
			// clear plain for check decryption function
			plain[0] = '\0'; 
			//dec
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_DEC_VALUE,
									 &op, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_RSA_CMD_DEC_VALUE) failed 0x%x origin 0x%x\n",
					res, err_origin);
			printf("\nThe text sent was decrypted: %s\n", plain);
			write_file("rsaPlain.txt", plain, 0);
		}
	}else { // Exception for invalid argument
		printf("Invalid argument %s\n", argv[1]);
		return 1;
	}
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
