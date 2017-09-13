/*
 * Author: Aananth C N
 * email: c.n.aananth@gmail.com
 *
 * License: MPL v2
 * Original Date: 10 Jul 2015
 * Modified Date: 10 Sep 2017
 */

#ifndef EASY_JSON_H
#define EASY_JSON_H

extern "C" {
	#include <jansson.h>
}

#define BUFF_SIZE	(1024)
#define NAME_SIZE	(128)
#define PATH_SIZE	(256)


typedef json_t ej_t;


class EasyJson
{
public:
	EasyJson();
	~EasyJson();

	int load_buf(char *buf, json_t ** root);
	int store_buf(json_t * root, char *buf, int max);
	int load_file(char *file, json_t ** root);
	int store_file(json_t * root, char *file);
	int get_int(json_t * root, char *name, int *value);
	int get_string(json_t * root, char *name, char *value);
	int set_int(json_t * root, char *name, int value);
	int set_string(json_t * root, char *name, char *value);
	int add_int(json_t ** root, char *name, int value);
	int add_string(json_t ** root, char *name, char *value);
	int free_ref(json_t *json);
	int get_array(json_t *jarray, int index, json_t **jrow);
	int get_array_n(json_t *jarray, int *n);
	int get_array_obj(json_t *root, char *name, json_t **jarray);
};

#endif
