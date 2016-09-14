/*
 * Copyright (c) 2016, Tom G., <geiselto@hs-albsig.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Created:		09.07.2016
 * Last modified:	13.09.2016
 *
 */

#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>

#define PNG_MAGIC		(unsigned int) 0x89504e470d0a1a0a	/* Hex PNG magic byte wrapped around to match first read byte */
#define BIN_MAGIC		'\0'					/* NUL Byte */
#define HMAC			".hmac"

enum {
	MAX_TYPES = 2,							/* 2 directories to compare */
	MAX_ELEM = 128, 						/* Max. number of elements which fit into buffer */
	MAX_LEN = 256,							/* Max. dir-/file-path length */
	NBYTES = 16,							/* Bytes to be read from files to identify binaries */
};

static struct rdtool {
	char elem[MAX_ELEM][MAX_LEN];
	char cmpelem[MAX_ELEM][MAX_LEN];
	char type[MAX_TYPES][MAX_ELEM][MAX_LEN];
	char cmd[MAX_LEN];
} rd;

static int is_dir(const char *path)
{
	struct stat st;

	return path && !stat(path, &st) && S_ISDIR(st.st_mode);
}

static inline bool __attribute__((unused)) strrsstrcmp(char *s1, char *s2, char delim, off_t off)
{
	char *ptr1 = &s1[strlen(s1) - (unsigned) off], *ptr2 = &s2[strlen(s2) - (unsigned) off];

	for ( ; *ptr1 != delim; ) {
		if (*--ptr1 != *--ptr2)
			return false;
	}

	return true;
}

static int invoke_diff_wrapper(char **fls, const char *opts)
{
	char *cmd = calloc((strlen(rd.cmd) + strlen(opts) + strlen(fls[0]) + strlen(fls[1]) + 6), 1);

	if (!cmd)
		return -ENOMEM;

	printf("%-40s\t\t\t%-40s\n", fls[0], fls[1]);

	snprintf(cmd, (strlen(rd.cmd) + strlen(opts) + strlen(fls[0]) + strlen(fls[1]) + 5), "%s %s %s %s", rd.cmd, opts, fls[0], fls[1]);

	if (system(cmd) < 0) {
		free(cmd);
		return -errno;
	}

	free(cmd);

	return 0;
}

static int list_each_in_dir(const char *path)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	char *elem_path;
	int i = 0, j, pos;

	dir = opendir(path);
	if (!dir)
		return -errno;

	/* Scan specified dir */
	while ((dent = readdir(dir)) > (struct dirent *) NULL) {
		if (!memcmp(dent->d_name, ".", 1) || !memcmp(dent->d_name, "..", 2))
			continue;

		elem_path = calloc((strlen(path) + strlen(dent->d_name) + 3), 1);
		if (!elem_path)
			return -ENOMEM;

		snprintf(elem_path, (strlen(path) + strlen(dent->d_name) + 2), "%s/%s", path, dent->d_name);

		if (stat(elem_path, &st) < 0) {
			free(elem_path);
			continue;
		}

		if (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))
			memcpy(rd.elem[i], elem_path, strlen(elem_path) + 1);

		free(elem_path);
		i++;
	}
	closedir(dir);

	for (pos = i, i = 0; i < MAX_ELEM; i++) {
next:
		if (rd.elem[i] == '\0')
			continue;

		dir = opendir(rd.elem[i]);
		if (!dir)
			continue;

		for (j = 0; ; j++, pos++) {
			dent = readdir(dir);
			if (!dent) {
				closedir(dir);
				i++;
				goto next;
			}

			if (!memcmp(dent->d_name, ".", 1) || !memcmp(dent->d_name, "..", 2))
				continue;

			if (stat(rd.elem[i], &st) < 0)
				continue;

			if (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))
				snprintf(rd.elem[pos], (strlen(rd.elem[i]) + strlen(dent->d_name) + 2), "%s/%s", rd.elem[i], dent->d_name);
		}

	}
	closedir(dir);

	return 0;
}

static int get_file_types(int type)
{
	FILE *f;
	char *buf;
	int i, j;

	if (type < 0 || type > 1)
		return -EINVAL;

	for (i = 0; i < MAX_ELEM; i++) {
		if (rd.elem[i] == '\0')
			continue;

		if (strstr(rd.elem[i], HMAC)) {
			memcpy(rd.type[type][i], "HMAC", 5);
			continue;
		}

		f = fopen(rd.elem[i], "r");
		if (!f)
			continue;

		if (fseek(f, 0, SEEK_END)) {
			fclose(f);
			continue;
		}
		/* Filter out single byte junk (e.g. /lib/firmware/emmc/catalog.txt) */
		if (ftell(f) == 1) {
			memcpy(rd.type[type][i], "Empty", 6);
			fclose(f);
			continue;
		}
		rewind(f);

		buf = calloc(strlen(rd.elem[i]) + 1, 1);
		if (!buf)
			return -ENOMEM;

		/* First NBYTES seem to be sufficient */
		if (!fread(buf, NBYTES, 1, f)) {
			if (ferror(f))
				goto next;
		}

		if (buf[0] == PNG_MAGIC)  {
			memcpy(rd.type[type][i], "PNG", 4);
			goto next;
		}


		/* If NUL byte found file likely a binary */
		for (j = 0; j < NBYTES; j++) {
			if (buf[j] == BIN_MAGIC) {
				memcpy(rd.type[type][i], "Bin", 4);
				goto next;
			}
		}
		memcpy(rd.type[type][i], "Other", 6);
next:
		fclose(f);
		free(buf);
	}

	return 0;
}

static int setup_and_cmp_dirs(const char **paths)
{
	char *tmp[MAX_TYPES];
	int i, j, ret;

	for (i = 0; i < 2; i++) {
		ret = list_each_in_dir(paths[i]);
		if (ret)
			return ret;

		ret = get_file_types(i);
		if (ret)
			return ret;

		if (!i) {
			for (j = 0; j < MAX_ELEM; j++) {
				if (rd.elem[j] == '\0' || is_dir(rd.elem[j]) || memcmp(rd.type[i][j], "Other", 6))
					continue;

				memcpy(rd.cmpelem[j], rd.elem[j], strlen(rd.elem[j]) + 1);
			}
		}
	}

	for (i = 0; i < MAX_ELEM; i++) {
		if (rd.elem[i] == '\0' || is_dir(rd.elem[i]) || memcmp(rd.type[1][i], "Other", 6))
			continue;

		*tmp = rd.cmpelem[i];
		tmp[1] = rd.elem[i];

		ret = invoke_diff_wrapper(tmp, "-ay --suppress-common-lines");
		if (ret)
			return ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *paths[MAX_TYPES];
	int i, ret, pos;

	if (argc < 3 || argc > 4) {
		printf("Invalid number of supplied arguments\nUsage: rdtool (-c) ramdisk1 ramdisk2\n");
		return -EINVAL;
	}

	argc == 3 ? (pos = 1) : (pos = 2);

	for (i = pos; i < pos + 2; i++) {
		if (!is_dir(argv[i])) {
			printf("Failed, specified Path %s no valid directory\nUsage: rdtool (-c) ramdisk1 ramdisk2\n", argv[i]);
			return -EINVAL;
		}
	}

	if (argc == 4) {
		if (!memcmp(argv[1], "-c", 3))
			memcpy(rd.cmd, "colordiff", 10);
	} else {
		memcpy(rd.cmd, "diff", 5);
	}

	*paths = argv[pos];
	paths[1] = argv[++pos];

	ret = setup_and_cmp_dirs(paths);
	if (ret)
		printf("Failed: %s\n", strerror(errno));

	return 0;
}
