/*
 * Author: Aananth C N
 * email: c.n.aananth@gmail.com
 *
 * License: MPL v2
 * Date: 10 July 2015
 */

extern "C" {
	#include <stdio.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <string.h>
	#include <unistd.h>

	#include <jansson.h>
}

#include "EasyJson.h"



EasyJson::EasyJson() {
}

EasyJson::~EasyJson() {

}


/*                    E A S Y   J S O N   A P I ' S                     */

/*************************************************************************
 * function: EasyJson::load_buf
 *
 * This function json formated text buffer into json structure so that
 * application can parse and get json values.
 *
 * arg1: buffer pointer
 * arg2: json_t pointer reference
 *
 * return: positive or negative number
 */
int EasyJson::load_buf(char *buf, json_t ** root)
{
	int flags = 0;

	json_error_t error;

	if (!buf) {
		printf("%s(), invalid arguments!\n", __func__);
		return -1;
	}

	*root = json_loads(buf, flags, &error);
	if (*root == NULL) {
		printf("error: %s\n", error.text);
		return -1;
	}

	return 0;
}

/*************************************************************************
 * function: EasyJson::store_buf
 *
 * This function stores the encoded json structure into RAM buffer
 *
 * arg1: json object pointer
 * arg2: buffer pointer
 * arg3: max size of buffer
 *
 * return: positive or negative number
 */
int EasyJson::store_buf(json_t * root, char *buf, int max)
{
	if ((root == NULL) || (buf == NULL)) {
		printf("Error: %s(): invalid arguments\n", __func__);
		return -1;
	}

	strncpy(buf, json_dumps(root, 0), max);

	return 0;
}

/*************************************************************************
 * function: EasyJson::load_file
 *
 * This function copies json file to RAM area, do necessary checks and
 * pass back json_t* (pointer to the RAM area), to the caller
 *
 * arg1: file path of json file
 * arg2: json_t pointer reference
 *
 * return: positive or negative number
 */
int EasyJson::load_file(char *file, json_t ** root)
{
	int flags = 0;

	json_error_t error;

	if (!file) {
		printf("%s(), invalid file passed!\n", __FUNCTION__);
		return -1;
	}

	*root = json_load_file(file, flags, &error);
	if (*root == NULL) {
		printf("error: %s, line %d: %s\n", file,
		       error.line, error.text);
		return -1;
	}

	return 0;
}

/*************************************************************************
 * function: EasyJson::store_file
 *
 * This function stores the data in RAM pointed by json_t* to the storage
 * media path passed as argument
 *
 * arg1: file path
 * arg2: json_t pointer
 *
 * return: positive or negative number
 */
int EasyJson::store_file(json_t * root, char *file)
{
	int flags, ret;

	if (!file) {
		printf("%s(), invalid file passed!\n", __FUNCTION__);
		return -1;
	}

	/* dump to a temporary file */
	flags = JSON_INDENT(8);
	ret = json_dump_file(root, file, flags);
	if (ret < 0)
		return -1;

	return 0;
}

/*************************************************************************
 * function: EasyJson::get_int
 *
 * This function gets the integer value from the json object
 *
 * return: positive or negative number
 */
int EasyJson::get_int(json_t * root, char *name, int *value)
{
	json_t *obj;

	obj = json_object_get(root, name);
	if (obj == NULL) {
		*value = 0;
		printf("%s(): %s is not a valid object\n", __func__, name);
		return -1;
	}

	if (json_is_integer(obj)) {
		*value = json_integer_value(obj);
		return 0;
	}
	else {
		printf("%s(): %s is not an integer\n", __func__, name);
		*value = -1;
		return -1;
	}
}

/*************************************************************************
 * function: EasyJson::get_string
 *
 * This function gets the string value from the json object
 *
 * return: positive or negative number
 */
int EasyJson::get_string(json_t * root, char *name, char *value)
{
	json_t *obj;

	if (!json_is_object(root)) {
		printf("%s(): invalid json arg passed\n", __FUNCTION__);
		return -1;
	}

	obj = json_object_get(root, name);
	if (obj == NULL) {
		*value = '\0';
		return -1;
	}

	if (json_is_string(obj)) {
		strcpy(value, json_string_value(obj));
		return 0;
	}
	else {
		printf("%s(): %s is not a string!\n", __func__, name);
		return -1;
	}
}

/*************************************************************************
 * function: EasyJson::set_int
 *
 * This function sets the integer value to the json object
 *
 * return: positive or negative number
 */
int EasyJson::set_int(json_t * root, char *name, int value)
{
	json_t *obj;

	obj = json_object_get(root, name);
	if (obj == NULL) {
		return -1;
	}

	if (json_is_integer(obj)) {
		return json_integer_set(obj, value);
	}
	else {
		printf("%s(): %s is not an integer\n", __func__, name);
		return -1;
	}
}

/*************************************************************************
 * function: EasyJson::set_string
 *
 * This function gets the string value to the json object
 *
 * return: positive or negative number
 */
int EasyJson::set_string(json_t * root, char *name, char *value)
{
	json_t *obj;

	obj = json_object_get(root, name);
	if (obj == NULL) {
		return -1;
	}

	if (json_is_string(obj)) {
		return json_string_set(obj, value);
	}
	else {
		printf("%s(): %s is not a string!\n", __func__, name);
		return -1;
	}
}

int EasyJson::add_int(json_t ** root, char *name, int value)
{
	json_t *new;

	if (name == NULL) {
		printf("%s(): invalid arguments!\n", __func__);
		return -1;
	}

	new = json_pack("{\nsi\n}", name, value);
	if (new == NULL)
		return -1;

	return json_object_update(*root, new);
}

int EasyJson::add_string(json_t ** root, char *name, char *value)
{
	json_t *new;

	if ((name == NULL) || (value == NULL)) {
		printf("%s(): invalid arguments!\n", __func__);
		return -1;
	}

	new = json_pack("{\nss\n}", name, value);
	if (new == NULL)
		return -1;

	return json_object_update(*root, new);
}


int EasyJson::get_array_obj(json_t *root, char *name, json_t **jarray)
{

	int n = 0;

	if ((name == NULL) || ( NULL == root) || (NULL == jarray)) {
		printf(" %s(): invalid arguements!\n", __func__);
		return -1;
	}

	*jarray = json_object_get(root, name);
	if((*jarray == NULL) || (0 == (n = json_array_size(*jarray)))) {
		printf("%s(): no array obj found\n", __FUNCTION__);
		return -1;
	}

	return 0;

}

int EasyJson::get_array_n(json_t *jarray, int *n)
{
	if ((NULL == jarray) || (NULL == n)) {
		printf(" %s(): invalid arguements!\n", __func__);
		return -1;
	}

	*n = json_array_size(jarray);
	if (*n <= 0){
		printf(" %s(): Invalid array element count!\n", __func__);
		return -1;
	}

	return 0;

}

int EasyJson::get_array(json_t *jarray, int index, json_t **jrow)
{

	if ((jrow == NULL) || (NULL == jarray)) {
		printf(" %s(): invalid arguements!\n", __func__);
		return -1;
	}

	*jrow = json_array_get(jarray, index);
	if(!json_is_object(*jrow)) {
		printf(" %s(): Invalid object for array\n", __func__);
		return -1;
	}

	return 0;
}


int EasyJson::free_ref(json_t *json)
{
	if (NULL == json) {
		printf(" %s(): invalid arguements!\n", __func__);
		return -1;
	}
	json_decref(json);

	return 0;
}
